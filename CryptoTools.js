const crypto = require('crypto');

/**
 * 带完整调试日志的ECDSA验签函数（适配你的客户端格式）
 * @param {string} userId - 上传的用户ID（如user_92648）
 * @param {string} signatureBase64 - 客户端上传的signature
 * @param {string} ecdsaPubKeyBase64 - 客户端上传的ecdsaPubKey
 * @returns {boolean} 验签结果
 */
function verifySignature(userId, signatureBase64, ecdsaPubKeyBase64) {
    // console.log('\n==================== 验签调试开始 ====================');
    // console.log('【输入参数】');
    // console.log('userId:', userId);
    // console.log('signatureBase64长度:', signatureBase64?.length || 'undefined');
    // console.log('ecdsaPubKeyBase64长度:', ecdsaPubKeyBase64?.length || 'undefined');

    // 1. 基础参数校验
    if (!userId || !signatureBase64 || !ecdsaPubKeyBase64) {
        // console.error('【错误】参数为空 → 返回false');
        // console.log('==================== 验签调试结束 ====================\n');
        return false;
    }

    try {
        // 2. 解码Base64并验证长度
        // console.log('\n【步骤1：解码Base64】');
        const pubKeyBuf = Buffer.from(ecdsaPubKeyBase64, 'base64');
        const sigBuf = Buffer.from(signatureBase64, 'base64');
        
        // console.log('公钥解码后字节长度:', pubKeyBuf.length);
        // console.log('公钥解码后前10字节(hex):', pubKeyBuf.slice(0, 10).toString('hex'));
        // console.log('签名解码后字节长度:', sigBuf.length);
        // console.log('签名解码后前10字节(hex):', sigBuf.slice(0, 10).toString('hex'));

        // 验证P-256标准长度
        if (pubKeyBuf.length !== 65) {
            // console.error(`【错误】公钥长度错误（标准65字节，实际${pubKeyBuf.length}字节）→ 返回false`);
            // console.log('==================== 验签调试结束 ====================\n');
            return false;
        }
        if (sigBuf.length !== 64) {
            // console.error(`【错误】签名长度错误（标准64字节，实际${sigBuf.length}字节）→ 返回false`);
            // console.log('==================== 验签调试结束 ====================\n');
            return false;
        }

        // 3. 转换公钥为PEM格式（Node.js兼容）
        // console.log('\n【步骤2：转换公钥为PEM格式】');
        const spkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
        const spkiDer = Buffer.concat([spkiPrefix, pubKeyBuf]);
        const pemBase64 = spkiDer.toString('base64').match(/.{1,64}/g).join('\n');
        const pem = `-----BEGIN PUBLIC KEY-----\n${pemBase64}\n-----END PUBLIC KEY-----`;
        
        // console.log('PEM格式公钥:\n', pem);

        // // 4. 转换签名为DER格式（Node.js兼容）
        // console.log('\n【步骤3：转换签名为DER格式】');
        // 拆分r/s（各32字节）
        const r = sigBuf.slice(0, 32);
        const s = sigBuf.slice(32, 64);
        // console.log('签名r部分(hex):', r.toString('hex'));
        // console.log('签名s部分(hex):', s.toString('hex'));

        // 清理r/s的前导0（ASN.1规范）
        const trimLeadingZero = (buf) => {
            let i = 0;
            while (i < buf.length && buf[i] === 0) i++;
            const trimmed = i === buf.length ? Buffer.from([0]) : buf.slice(i);
            // console.log(`清理前导0后长度(${i===0?'无变化':'移除'+i+'字节'}):`, trimmed.length);
            return trimmed;
        };
        const rTrimmed = trimLeadingZero(r);
        const sTrimmed = trimLeadingZero(s);

        // 补前导0（避免负数，ASN.1规范）
        const addLeadingZeroIfNeeded = (buf) => {
            const needPad = (buf[0] & 0x80) === 0x80;
            const padded = needPad ? Buffer.concat([Buffer.from([0]), buf]) : buf;
            // console.log(`补前导0(${needPad?'是':'否'}):`, padded.length);
            return padded;
        };
        const rFinal = addLeadingZeroIfNeeded(rTrimmed);
        const sFinal = addLeadingZeroIfNeeded(sTrimmed);

        // 构建DER结构
        const rSeq = Buffer.concat([Buffer.from([0x02, rFinal.length]), rFinal]);
        const sSeq = Buffer.concat([Buffer.from([0x02, sFinal.length]), sFinal]);
        const sigDer = Buffer.concat([
            Buffer.from([0x30, rSeq.length + sSeq.length]),
            rSeq,
            sSeq
        ]);
        // console.log('DER格式签名(hex):', sigDer.toString('hex'));
        // console.log('DER签名长度:', sigDer.length);

        // // 5. 验签核心逻辑（输出原始验签数据）
        // console.log('\n【步骤4：执行验签】');
        // console.log('待验签的原始数据(userId):', userId);
        // console.log('待验签数据的SHA256哈希:', crypto.createHash('sha256').update(userId).digest('hex'));

        const verify = crypto.createVerify('sha256');
        verify.write(userId);
        verify.end();

        // 执行验签（关键：输出验签过程的原始结果）
        const isVerified = verify.verify(pem, sigDer);
        // console.log('\n【最终结果】验签是否成功:', isVerified);
        // console.log('==================== 验签调试结束 ====================\n');

        return isVerified;
    } catch (err) {
        // console.error('\n【异常】验签过程出错:', err);
        // console.log('==================== 验签调试结束 ====================\n');
        return false;
    }
}

// // 测试你的示例值（直接运行该文件即可看到调试日志）
// const testUserId = 'user_92648';
// const testSig = 'Jo6nQZc9zEt2TyQBy3tf1e69LCFnUvdqsxXMRfgvw4zlK5vvBWU/I7Qqu3zm1TFdAyGJxtVCbznbhq9BzBjwZg==';
// const testPubKey = 'BGnZswe1bJ0MpJ7T2Ro5E+jSjjXDvEuUotxDJtEDFGt/8m6yXVZ5fjvhfohKeKZhnlxHB1EE9B1V2t7HzZVCKAs=';

// // 执行测试
// console.log('===== 测试你的示例值开始 =====');
// const result = verifySignature(testUserId, testSig, testPubKey);
// console.log('===== 测试结果:', result ? '验签成功' : '验签失败');

module.exports.verifySignature = verifySignature;