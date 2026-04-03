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
    const parsedUrl = url.parse(req.url, true);
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
    let getPubKey = () => {
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
                    console.log('111')
                    console.log(msg);
                    console.log(userID);
                    // 验签
                    const isAuthValid = verifySignature(userID, signature, ecdsaPubKey);
                    if (!isAuthValid) {
                        usersList.set(userID, { wsConnection: ws, userID, });
                        ws.send(JSON.stringify({ type: 'replyUploadPublicKey', success: false }));
                    }
                    else {
                        fs.writeFileSync(path.join(userDir, "ECDSA.pub"), ecdsaPubKey);
                        fs.writeFileSync(path.join(userDir, "ECDH.pub"), ecdhPubKey);
                        ws.send(JSON.stringify({ type: "replyUploadPublicKey", success: true, userID }));
                    }
                }
                break;
            case "loadUser":
                //用户上传userID的签名，用私钥加密。
                //服务器用公钥验证签名是否正确。
                {
                    if(userID){
                        onlineUsersList.delete(userID)
                    }
                    userID = msg.userID;
                    let signature = msg.signature;
                    let {ecdsaPubKey, ecdhPubKey} = getPubKey();
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
                }
                break;
            case "getOnlineUsersList":
                {
                    if(userID){
                        ws.send(JSON.stringify({
                            type: 'replyGetOnlineUsersList',
                            onlineUsersList: Array.from((onlineUsersList).keys())
                        }));
                    }
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
    console.log(`信令服务器启动：https://localhost:${PORT}`);
});