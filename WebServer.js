const checkSSL = require("./GenerateSSL").checkSSL;

checkSSL();


const https = require('https');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const { usersSSLDir } = require("./GenerateSSL");
const verifySignature = require("./CryptoTools").verifySignature;
const url = require('url');
const { ECDH } = require("crypto");
const { type } = require("os");

// 1. 读取SSL证书
const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'ssl/key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'ssl/cert.pem'))
};

// 2. 简单的模板渲染函数（模拟模板引擎，适合毕业设计）
function renderTemplate(templatePath) {
    // 读取模板文件
    let template = fs.readFileSync(templatePath, 'utf8');
    return template;
}

// 3. 创建HTTPS服务器
const httpsServer = https.createServer(sslOptions, (req, res) => {
    const base = `https://${req.headers.host}`;
    const parsedUrl = new URL(req.url, base);
    const pathname = parsedUrl.pathname;

    // 设置响应头（UTF-8编码，解决中文乱码）
    res.setHeader('Content-Type', 'text/html; charset=utf-8');

    // 路由处理
    switch (pathname) {
        case '/index.html':
        case '/':
            // 渲染首页模板
            const homeHtml = renderTemplate(path.join(__dirname, 'templates/index.html'));
            res.writeHead(200);
            res.end(homeHtml);
            break;
        case '/crypto.js':
            res.writeHead(200);
            res.end(renderTemplate(path.join(__dirname, 'templates', pathname)));
            break;
        // 404页面
        default:
            res.writeHead(404);
            res.end(renderTemplate(path.join(__dirname, 'templates/404.html')));
            break;
    }
});

// 启动WebSocket服务（基于HTTPS）
const wss = new WebSocket.Server({ server: httpsServer });
let usersList = new Map();
let onlineUsersList = new Map();
let usersSSLDirList = fs.readdirSync(usersSSLDir);
usersSSLDirList.forEach((value) => {
    usersList.set(value, {
        wsConnection: null,
        value
    })
})

wss.on('connection', (ws) => {
    let userID = null;
    let userDir = null;
    // 生成随机用户ID
    let generateUserID = () => {
        let userID = null;
        do {
            userID = `user_${Math.floor(Math.random() * 100000)}`;
        }
        while (usersList.has(userID));
        console.log(userID);
        return userID;
    }
    let addNewUser = () => {
        let userID = generateUserID();
        userDir = path.join(usersSSLDir, userID);
        fs.mkdirSync(userDir);
        fs.writeFileSync(path.join(userDir, "createTime.info"), (new Date()).toUTCString());
        return userID;
    }
    let getPubKey = (userID) => {
        userDir = path.join(usersSSLDir, userID);
        return {
            ecdsaPubKey: fs.readFileSync(path.join(userDir, "ECDSA.pub")).toString(),
            ecdhPubKey: fs.readFileSync(path.join(userDir, "ECDH.pub")).toString(),
        }
    }
    ws.on('message', (data) => {
        const msg = JSON.parse(data);
        switch (msg.type) {
            case "newUser":
                userID = addNewUser();
                ws.send(JSON.stringify({ type: "replyNewUser", userID }));
                break;
            case "uploadPublicKey":
                {
                    userID = msg.userID;
                    let ecdsaPubKey = msg.ecdsaPubKey;
                    let ecdhPubKey = msg.ecdhPubKey;
                    let signature = msg.signature;
                    // console.log('111')
                    // console.log(msg);
                    // console.log(userID);
                    // 验签
                    const isAuthValid = verifySignature(userID, signature, ecdsaPubKey);
                    if (!isAuthValid) {
                        ws.send(JSON.stringify({ type: 'replyUploadPublicKey', success: false }));
                    }
                    else {
                        usersList.set(userID, { wsConnection: ws, userID, });
                        fs.writeFileSync(path.join(userDir, "ECDSA.pub"), ecdsaPubKey);
                        fs.writeFileSync(path.join(userDir, "ECDH.pub"), ecdhPubKey);
                        ws.send(JSON.stringify({ type: "replyUploadPublicKey", success: true, userID }));
                    }
                }
                break;
            case "loadUser":
                //用户上传userID的签名，用私钥加密。
                //服务器用公钥验证签名是否正确。
                try {
                    // console.log(usersList.keys());
                    if(!usersList.has(msg.userID)){
                        ws.send(JSON.stringify({
                            type: "replyLoadUser",
                            success: false,
                        }))
                        return;
                    }
                    if(userID){
                        onlineUsersList.delete(userID)
                    }
                    userID = msg.userID;
                    let signature = msg.signature;
                    let {ecdsaPubKey, ecdhPubKey} = getPubKey(userID);
                    const checkSignature = verifySignature(userID, signature, ecdsaPubKey);
                    if (checkSignature) {
                        onlineUsersList.set(userID, { wsConnection: ws, userID, });
                        ws.send(JSON.stringify({
                            type: "replyLoadUser",
                            success: true,
                            userID
                        }))
                    }
                    else {
                        ws.send(JSON.stringify({ type: 'replyUploadPublicKey', success: false }));

                    }
                }catch(e) {
                    ws.send(JSON.stringify({ type: 'replyLoadUser', success: false }));
                }
                break;
            case "getOnlineUsersList":
                {
                    if(userID){
                        ws.send(JSON.stringify({
                            type: 'replyGetOnlineUsersList',
                            onlineUsersList: Array.from((onlineUsersList).keys()).filter(id => id !== userID),
                        }));
                    }
                }
                break;
            case "WebRTCcaller":
                try{
                    let targetUser = msg.targetUser;
                    let offer = msg.offer;
                    if(onlineUsersList.has(targetUser)){
                        let targetUserObject = onlineUsersList.get(targetUser);
                        let {ecdsaPubKey: sourceUserECDSAPubKey, ecdhPubKey: sourceUserECDHPubKey} = getPubKey(userID);
                        let signature = msg.signature;

                        // console.log(getPubKey(userID));

                        targetUserObject.wsConnection.send(JSON.stringify({
                            type: "WebRTCcallee",
                            sourceUser: userID,
                            targetUser,
                            offer,
                            sourceUserECDHPubKey,
                            sourceUserECDSAPubKey,
                            signature,
                        }))
                    }
                }catch(e){
                    console.log(e.message)
                }
                break;
            case "WebRTCcalleeAnswer":
                {
                    //这是callee发来的Answer
                    let sourceUser = msg.sourceUser;
                    let answer = msg.answer;
                    if(onlineUsersList.has(sourceUser)){
                        let {ecdsaPubKey: targetUserECDSAPubKey, ecdhPubKey: targetUserECDHPubKey} = getPubKey(userID);
                        let sourceUserObject = onlineUsersList.get(sourceUser);
                        let signature = msg.signature;
                        sourceUserObject.wsConnection.send(JSON.stringify({
                            type: "WebRTCcallerAnswer",
                            sourceUser,
                            targetUser: userID,
                            answer,
                            targetUserECDSAPubKey,
                            targetUserECDHPubKey,
                            signature
                        }))
                    }
                }
                break;
            case "WebRTCice":
                try {
                    // 转发 ICE 到目标用户
                    let targetUser = msg.targetUser;
                    let candidate = msg.candidate;

                    if (onlineUsersList.has(targetUser)) {
                        let target = onlineUsersList.get(targetUser);
                        target.wsConnection.send(JSON.stringify({
                            type: "WebRTCice",
                            candidate: candidate
                        }));
                    }
                } catch (e) {
                    console.log("ICE 转发错误", e.message);
                }
                break;
        }
    });

    // 连接关闭清理
    ws.on('close', () => {
        onlineUsersList.delete(userID);
    });

    // 发送错误信息
    ws.sendError = (message) => {
        ws.send(JSON.stringify({ type: 'error', message }));
    };
});


// 启动服务器
const PORT = 4430;
httpsServer.listen(PORT, () => {
    console.log(`Server Address: https://localhost:${PORT}`);
});