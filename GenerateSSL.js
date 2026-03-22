const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// 证书存放目录
const sslDir = path.join(__dirname, 'ssl');
const usersSSLDir = path.join(__dirname, 'usersSSL');

let checkSSL = () => {
    if (!fs.existsSync(sslDir)) {
        fs.mkdirSync(sslDir);
        generateSSL();
    }
    if(!fs.existsSync(usersSSLDir)) {
        fs.mkdirSync(usersSSLDir);
    }
}

let generateSSL = () => {

    // OpenSSL 命令（生成自签名证书，有效期365天）
    const sslCommands = [
        `openssl req -x509 -newkey rsa:4096 -keyout ${sslDir}/key.pem -out ${sslDir}/cert.pem -days 365 -nodes`,
        `-subj "/C=CN/ST=Beijing/L=Beijing/O=E2EE/CN=localhost"` // 证书信息（可自定义）
    ].join(' ');

    try {
        console.log('正在生成SSL证书...');
        // 执行OpenSSL命令
        execSync(sslCommands, { stdio: 'inherit' });
        console.log(`证书生成成功！路径：${sslDir}`);
        console.log('注意：自签名证书在浏览器中会提示"不安全"，仅用于开发/毕业设计');
    } catch (err) {
        console.error('证书生成失败：', err.message);
        console.error('请确保已安装OpenSSL并配置环境变量');
    }

}

module.exports.checkSSL = checkSSL;
module.exports.usersSSLDir = usersSSLDir;