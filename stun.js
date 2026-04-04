// ==============================================
// 纯 Node.js 原生 STUN 服务器（信息安全项目专用）
// 无依赖、不报错、Buffer 安全不越界
// ==============================================
const dgram = require('dgram');
const STUN_PORT = 3478;
const stunServer = dgram.createSocket('udp4');

stunServer.on('message', (msg, rinfo) => {
  try {
    // 只处理 STUN Binding Request
    if (msg.length >= 20 && msg[0] === 0x00 && msg[1] === 0x01) {
      // 新建安全长度的 Buffer（不会越界）
      const response = Buffer.alloc(100);
      
      // 复制 STUN 头
      msg.copy(response, 0, 0, 20);
      
      // 响应类型：Binding Success Response
      response.writeUInt16BE(0x0101, 0);
      // 消息长度（不包含头 20 字节）
      response.writeUInt16BE(12, 2);
      
      // XOR-MAPPED-ADDRESS 属性
      response.writeUInt16BE(0x0020, 20); // 属性类型
      response.writeUInt16BE(8, 22);     // 属性长度
      response[24] = 0;                  // 保留位
      response[25] = 0x01;                // IPv4
      
      // 写入端口（XOR 处理）
      const xorPort = rinfo.port ^ 0x2112;
      response.writeUInt16BE(xorPort, 26);
      
      // 写入 IP（XOR 处理）
      const ipParts = rinfo.address.split('.').map(Number);
      response[28] = ipParts[0] ^ 0x21;
      response[29] = ipParts[1] ^ 0x12;
      response[30] = ipParts[2] ^ 0xA4;
      response[31] = ipParts[3] ^ 0x42;
      
      // 发送响应
      stunServer.send(response.slice(0, 32), rinfo.port, rinfo.address);
    }
  } catch (err) {
    // 安全捕获错误，不崩溃
    // console.error('STUN处理错误:', err);
  }
});

stunServer.bind(STUN_PORT, '0.0.0.0', () => {
  console.log('==================================================');
  console.log('✅ 【安全自建】STUN 服务器运行中 → 端口：3478');
  console.log('==================================================');
});