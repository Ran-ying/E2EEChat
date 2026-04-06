// 客户端通用加密工具类（浏览器环境）
class CryptoUtils {
    // 1. 生成两类密钥对：
    // - ECDSA：用于签名/验签（身份认证）
    // - ECDH：用于加密/解密（消息传输）
    static async generateKeyPairs() {
        // ECDSA签名密钥对（不可提取私钥，更安全）
        const ecdsaKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true, // 私钥不可提取（防泄露）
            ['sign', 'verify']
        );

        // ECDH加密密钥对（可提取公钥，用于传输）
        const ecdhKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true, // 公钥可提取
            ['deriveKey', 'deriveBits']
        );

        // 导出公钥（转Base64，便于网络传输）
        const ecdsaPubKey = await this.exportPublicKey(ecdsaKeyPair.publicKey);
        const ecdhPubKey = await this.exportPublicKey(ecdhKeyPair.publicKey);

        return {
            // 私钥（仅客户端保存，永不发送）
            ecdsaPrivateKey: ecdsaKeyPair.privateKey,
            ecdhPrivateKey: ecdhKeyPair.privateKey,
            // 公钥（可发送给服务器/其他客户端）
            ecdsaPubKey,
            ecdhPubKey
        };
    }

    // 2. 导出公钥为Base64格式
    static async exportPublicKey(publicKey) {
        const rawKey = await crypto.subtle.exportKey('raw', publicKey);
        return btoa(String.fromCharCode(...new Uint8Array(rawKey)));
    }

    // 3. 导入公钥（用于验签/加密）
    static async importPublicKey(pubKeyBase64, type = 'ECDSA') {
        const rawKey = Uint8Array.from(atob(pubKeyBase64), c => c.charCodeAt(0));
        const algo = type === 'ECDSA'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        return crypto.subtle.importKey(
            'raw',
            rawKey,
            algo,
            false,
            type === 'ECDSA' ? ['verify'] : []
        );
    }

    // 4. 用ECDSA私钥签名身份信息（User_ID）
    static async signUserId(ecdsaPrivateKey, userId) {
        const encoder = new TextEncoder();
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            ecdsaPrivateKey,
            encoder.encode(userId)
        );
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    }

    // 5. 用ECDH公钥加密消息（或协商共享密钥）
    static async encryptWithPeerPubKey(ecdhPrivateKey, peerEcdhPubKeyBase64, message) {
        // 导入对方的ECDH公钥
        const peerPubKey = await this.importPublicKey(peerEcdhPubKeyBase64, 'ECDH');

        // 协商共享密钥（AES-256-GCM）
        const sharedKey = await crypto.subtle.deriveKey(
            { name: 'ECDH', public: peerPubKey },
            ecdhPrivateKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        // 用共享密钥加密消息
        const iv = crypto.getRandomValues(new Uint8Array(12)); // GCM推荐IV长度
        const encoder = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            sharedKey,
            encoder.encode(message)
        );

        return {
            iv: btoa(String.fromCharCode(...iv)),
            data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
        };
    }

    // 6. 用ECDH私钥解密消息
    static async decryptWithPrivateKey(ecdhPrivateKey, peerEcdhPubKeyBase64, encryptedData) {
        // 导入对方的ECDH公钥
        const peerPubKey = await this.importPublicKey(peerEcdhPubKeyBase64, 'ECDH');

        // 恢复共享密钥
        const sharedKey = await crypto.subtle.deriveKey(
            { name: 'ECDH', public: peerPubKey },
            ecdhPrivateKey,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        // 解密
        const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
        const ciphertext = Uint8Array.from(atob(encryptedData.data), c => c.charCodeAt(0));
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            sharedKey,
            ciphertext
        );

        return new TextDecoder().decode(decrypted);
    }
    // === 7. 验证 ECDSA 签名（你缺少的核心方法） ===
    static async verifySignature(ecdsaPubKeyBase64, originalData, signatureBase64) {
        try {
            // 1. 导入对方的 ECDSA 公钥
            const ecdsaPubKey = await this.importPublicKey(ecdsaPubKeyBase64, 'ECDSA');

            // 2. 把原始内容转成字节
            const encoder = new TextEncoder();
            const dataBytes = encoder.encode(originalData);

            // 3. 把签名 base64 转回字节
            const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

            // 4. 验证！
            const isValid = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' },
                ecdsaPubKey,
                signatureBytes,
                dataBytes
            );

            return isValid; // true = 验签成功
        } catch (e) {
            console.error('验签失败', e);
            return false;
        }
    }
}

////////////WS
class WS {
    // 静态属性需要通过类名访问，或用 this （静态方法中 this 指向类本身）
    static WSServerAddress = `wss://${window.location.host}`;
    static WSStatus = false; // WebSocket 连接状态
    static WSConnection = null; // WebSocket 实例
    static reconnectTimer = null; // 重连定时器

    // 初始化/重连 WebSocket 的核心函数
    static openWS = () => {
        // 关键修正：静态属性必须通过 WS.xxx 或 this.xxx 访问
        if (WS.reconnectTimer) {
            clearInterval(WS.reconnectTimer);
            WS.reconnectTimer = null;
        }

        // 创建新的 WebSocket 实例
        WS.WSConnection = new WebSocket(WS.WSServerAddress);

        // 连接成功
        WS.WSConnection.onopen = () => {
            WS.WSStatus = true;
            console.log("WebSocket 连接成功");
        };

        // 连接关闭
        WS.WSConnection.onclose = (event) => {
            WS.WSStatus = false;
            console.log(`WebSocket 断开，错误码：${event.code}，即将重连...`);
            // 启动重连定时器
            WS.reconnectTimer = setInterval(() => {
                WS.openWS();
            }, 1000);
        };

        // 连接错误
        WS.WSConnection.onerror = (error) => {
            WS.WSStatus = false;
            console.error("WebSocket 错误：", error);
            WS.WSConnection.close();
        };

        // 接收消息
        WS.WSConnection.onmessage = (event) => {
            console.log("收到消息：", event.data);
            // 可扩展：这里可以触发自定义事件，让外部处理消息
            WS.receiveMessage(JSON.parse(event.data));
        };
    };

    /**
     * 发送消息方法
     * @param {Object} object - 要发送的对象（会转为 JSON 字符串）
     * @returns {Object} - 发送结果：{ success: 布尔值, message: 提示信息 }
     */
    static sendMessage = (object) => {
        // 1. 校验连接状态
        if (!WS.WSStatus || !WS.WSConnection || WS.WSConnection.readyState !== WebSocket.OPEN) {
            return {
                success: false,
                message: "WebSocket 连接无效，无法发送消息（连接未建立/已关闭）"
            };
        }

        // 2. 校验入参
        if (typeof object !== "object" || object === null) {
            return {
                success: false,
                message: "发送失败：入参必须是非 null 的对象"
            };
        }

        try {
            // 3. 将对象转为 JSON 字符串发送（WebSocket 仅支持发送字符串/二进制）
            const message = JSON.stringify(object);
            WS.WSConnection.send(message);

            return {
                success: true,
                message: "消息发送成功",
                data: object // 可选：返回原始发送的对象，方便外部核对
            };
        } catch (error) {
            // 4. 捕获发送过程中的异常（如 JSON 序列化失败）
            return {
                success: false,
                message: `消息发送失败：${error.message}`,
                error: error // 可选：返回错误详情
            };
        }
    };

    static send = async (object) => {
        let sendPromise = () => {
            return new Promise((resolve, reject) => {
                let sendResult = WS.sendMessage(object);
                console.log("发送结果：", sendResult);
                if (sendResult.success) {
                    resolve(sendResult);
                }
                else {
                    reject(sendResult);
                }
            });
        }
        return new Promise((resolve, reject) => {
            let i = 1;
            let sendMessage = () => {
                setTimeout(async () => {
                    // 核心：await捕获reject的两种方式
                    try {
                        if (i > 10) {
                            reject();
                            return;
                        }
                        // 方式1：用try/catch捕获reject（推荐）
                        const sendResult = await sendPromise();
                        resolve(sendResult); // 成功时返回结果
                    } catch (error) {
                        // 捕获到reject的内容（就是sendResult）
                        console.error("发送失败：", error.message);
                        i++;
                        sendMessage();
                    }
                }, 1000)
            };
            sendMessage();
        })
    }

    // 手动关闭连接
    static closeWS = () => {
        if (WS.WSConnection) {
            WS.WSConnection.close();
        }
        if (WS.reconnectTimer) {
            clearInterval(WS.reconnectTimer);
            WS.reconnectTimer = null;
        }
        WS.WSStatus = true; // 修正：这里应该设为 false
        console.log("WebSocket 已手动关闭");
    };

    static receiveMessage = async (object) => {
        console.log(object.type);
        switch (object.type) {
            case "replyNewUser":
                WS.userID = object.userID;
                // console.log(object.type);
                WS.uploadPublicKey(WS.userID);
                return;
            case "replyUploadPublicKey":
                // console.log(object.success);
                if (object.success) {
                    // 存储到localStorage（私钥加密）
                    KeyStorage.saveKeyPairs(KeyStorage.keyPairs, WS.userID, WS.userPassword).then(() => {
                        loadOperatorUser();
                    }).then(() => {
                        // alert("success!")
                    });
                }
                return;
            case "replyLoadUser":
                if (object.success) {
                    WS.userID = object.userID;
                    document.getElementById('userID').textContent = object.userID;
                    WS.getOnlineUsersList();
                    // alert("success decrypt!");
                }
                else {
                    KeyStorage.deleteKeyPairs(WS.userID);
                    loadOperatorUser();
                }
                break;
            case "replyGetOnlineUsersList":
                WS.loadOnlineUsersList(object.onlineUsersList)
                break;
            case "WebRTCice": // ✅ 必须加！
                WebRTC.addIceCandidate(object.candidate);
                break;
            case "WebRTCcallee":
                //这是 Callee 收到服务器的消息，最终处理
                //验证caller签名
                const isCallerValid = await CryptoUtils.verifySignature(
                    object.sourceUserECDSAPubKey,
                    object.sourceUserECDHPubKey,
                    object.signature
                )
                if (isCallerValid) {
                    WebRTC.receivePeerConnection(object.offer, object.sourceUser).then(async (answer) => {
                        ;

                        WS.targetUser = object.sourceUser

                        WS.otherecdhPubKey = object.sourceUserECDHPubKey;
                        WS.otherecdsaPubKey = object.sourceUserECDSAPubKey;

                        document.getElementById("OOBmyUserID").innerHTML = WS.userID;
                        // document.getElementById("OOBmyECDH").innerHTML = await OOB.getEmojiFingerprint(WS.ecdhPubKey);
                        let myECDSA = await OOB.getEmojiFingerprint(WS.ecdsaPubKey);
                        document.getElementById("OOBmyECDSA").innerHTML = myECDSA;
                        document.getElementById("OOBotherUserID").innerHTML = object.sourceUser;
                        // document.getElementById("OOBotherECDH").innerHTML = await OOB.getEmojiFingerprint(WS.otherecdhPubKey);
                        let otherECDSA = await OOB.getEmojiFingerprint(WS.otherecdsaPubKey);
                        document.getElementById("OOBotherECDSA").innerHTML = otherECDSA;

                        document.getElementById("OOBinfo").innerHTML = `${otherECDSA} ${myECDSA}`

                        WebRTC.callerUserID = object.sourceUser;
                        WebRTC.calleeUserID = object.targetUser;

                        document.getElementById("OOBmyInfo").innerHTML = `(Me, Callee)`
                        document.getElementById("OOBotherInfo").innerHTML = `(Other, Caller)`
                        // document.getElementById("callee").innerHTML = object.targetUser;
                        // WebRTC.callerUserID = object.sourceUser;
                        // document.getElementById("caller").innerHTML = object.sourceUser;


                        // document.getElementById("OOBotherInfo").innerHTML += `✅`
                        //给出自己的 callee 签名
                        let signature = await CryptoUtils.signUserId(WS.ecdsaPrivateKey, WS.ecdhPubKey);
                        WS.send({
                            type: "WebRTCcalleeAnswer",
                            sourceUser: object.sourceUser,
                            answer,
                            signature,
                        })
                    });
                }
                else {
                    document.getElementById("OOBotherInfo").innerHTML += `❌`
                }
                break;
            case "WebRTCcallerAnswer":
                //这是 Caller 收到服务器的消息，最终处理

                //验证callee签名
                const isCalleeValid = await CryptoUtils.verifySignature(
                    object.targetUserECDSAPubKey,
                    object.targetUserECDHPubKey,
                    object.signature
                )
                if (isCalleeValid) {
                    WebRTC.setAnswerPeerConnection(object.answer).then(async () => {
                        WS.otherecdhPubKey = object.targetUserECDHPubKey;
                        WS.otherecdsaPubKey = object.targetUserECDSAPubKey;


                        WebRTC.callerUserID = object.sourceUser;
                        WebRTC.calleeUserID = object.targetUser;
                        // document.getElementById("callee").innerHTML = object.targetUser;
                        // WebRTC.callerUserID = object.sourceUser;
                        // document.getElementById("caller").innerHTML = object.sourceUser;
                        document.getElementById("OOBmyInfo").innerHTML = `(Me, Caller)`
                        document.getElementById("OOBotherInfo").innerHTML = `(Other, Callee)`


                        document.getElementById("OOBmyUserID").innerHTML = WS.userID;
                        // document.getElementById("OOBmyECDH").innerHTML = await OOB.getEmojiFingerprint(WS.ecdhPubKey);
                        let myECDSA = await OOB.getEmojiFingerprint(WS.ecdsaPubKey);
                        document.getElementById("OOBmyECDSA").innerHTML = myECDSA;
                        document.getElementById("OOBotherUserID").innerHTML = WebRTC.calleeUserID;
                        // document.getElementById("OOBotherECDH").innerHTML = await OOB.getEmojiFingerprint(WS.otherecdhPubKey);
                        let otherECDSA = await OOB.getEmojiFingerprint(WS.otherecdsaPubKey);
                        document.getElementById("OOBotherECDSA").innerHTML = otherECDSA;

                        document.getElementById("OOBinfo").innerHTML = `${myECDSA} ${otherECDSA}`

                        // document.getElementById("OOBotherInfo").innerHTML += `✅`
                    })
                }
                else {
                    document.getElementById("OOBotherInfo").innerHTML += `❌`
                }
        }
    }
    static userID = null;
    static userPassword = null;
    static newUser = () => {
        WS.userPassword = document.getElementById("userPassword").value;
        if (WS.userPassword.length < 1) {
            alert("password length > 1");
            return;
        }
        WS.send({
            type: "newUser"
        }).then(data => {
            console.log(data);
        }).catch(err => {
            console.log(err);
        })
    }

    static ecdsaPubKey;
    static ecdsaPrivateKey;
    static ecdhPubKey;
    static ecdhPrivateKey;
    static otherecdsaPubKey;
    static otherecdhPubKey;
    static loadUser = async () => {

        try {
            let loadUserPassword = document.getElementById("loadUserPassword").value;
            const {
                ecdsaPubKey,
                ecdsaPrivateKey,
                ecdhPubKey,
                ecdhPrivateKey,
                userID
            } = await KeyStorage.loadKeyPairs(WS.userID, loadUserPassword);;
            this.ecdsaPubKey = ecdsaPubKey;
            this.ecdsaPrivateKey = ecdsaPrivateKey;
            this.ecdhPubKey = ecdhPubKey;
            this.ecdhPrivateKey = ecdhPrivateKey;
            this.userID = userID;

            // 3. 签名User_ID
            const signature = await CryptoUtils.signUserId(this.ecdsaPrivateKey, userID);

            // 4. 连接WebSocket并提交公钥+签名（身份认证）
            WS.send({
                type: 'loadUser',
                userID,
                signature: signature               // 签名后的User_ID
            });
        }
        catch (e) {
            alert(e.message);
        }
    }

    static getOnlineUsersList = () => {
        WS.send({
            type: 'getOnlineUsersList'
        })
    }
    static loadOnlineUsersList = (onlineUsersList) => {
        // 3. 核心：将 keys 转换为 {value, label} 格式（forEach 实现）
        let keys = onlineUsersList;
        const optionData = [];
        keys.forEach(key => {
            // 填充选项格式
            optionData.push({
                value: key, // 选中时的取值（如 user_20700）
                label: key // 页面显示的文本
            });
        });
        renderRadioList("onlineUsersList", optionData, WS.bindOnlineUsersListChangeEvent);
    }
    static targetUser = null;
    static bindOnlineUsersListChangeEvent = (radioName, infoContainerId) => {
        const radioElements = document.querySelectorAll(`input[name="${radioName}"]`);
        const infoContainer = document.getElementById(infoContainerId);

        radioElements.forEach(radio => {
            radio.addEventListener('change', function () {
                if (this.checked) {
                    // 这里可添加选中后的业务逻辑（如读取对应用户的密钥）
                    WS.targetUser = this.value;
                }
            });
        });
    }
    static connectTargetUser = async () => {
        if (!this.targetUser) return;
        document.getElementById('targetUser').innerHTML = WS.targetUser;
        let offer = await WebRTC.createPeerConnection(this.targetUser);
        let signature = await CryptoUtils.signUserId(WS.ecdsaPrivateKey, WS.ecdhPubKey);
        WS.send({
            type: "WebRTCcaller",
            targetUser: WS.targetUser,
            offer,
            signature,
        })
    }
    // 6. 发送加密消息给其他客户端
    static sendEncryptedMessage = async (peerUserId, message) => {
    }
    static uploadPublicKey = async (userId) => {

        // ---------------- 客户端业务逻辑 ----------------
        // 页面加载时生成密钥对

        // 1. 生成密钥对
        KeyStorage.keyPairs = await CryptoUtils.generateKeyPairs();
        // 2. 
        // document.getElementById('userID').textContent = userId;

        // 3. 签名User_ID
        const signature = await CryptoUtils.signUserId(KeyStorage.keyPairs.ecdsaPrivateKey, userId);


        // 4. 连接WebSocket并提交公钥+签名（身份认证）
        WS.send({
            type: 'uploadPublicKey',
            userID: userId,
            ecdsaPubKey: KeyStorage.keyPairs.ecdsaPubKey, // ECDSA公钥（用于服务器验签）
            ecdhPubKey: KeyStorage.keyPairs.ecdhPubKey,   // ECDH公钥（用于其他客户端加密）
            signature: signature               // 签名后的User_ID
        });
    }
}

class OOB {
    // 64 个安全表情（和 Signal 一致）
    static EMOJIS = [
        '😀', '😁', '😂', '🤣', '😃', '😄', '😅', '😆',
        '😇', '😈', '👿', '😉', '😊', '😋', '😌', '😍',
        '😎', '😏', '😐', '😑', '😒', '😓', '😔', '😕',
        '😖', '😗', '😘', '😙', '😚', '😛', '😜', '😝',
        '😞', '😟', '😠', '😡', '😢', '😣', '😤', '😥',
        '😦', '😧', '😨', '😩', '😪', '😫', '🥱', '😬',
        '😭', '😮', '😯', '😰', '😱', '😲', '😳', '😴',
        '😵', '😷', '🤒', '🤕', '🤢', '🤮', '🤧', '🤠'
    ];

    static getEmojiFingerprint = async (ecdhPubKeyBase64) => {
        const rawKey = Uint8Array.from(atob(ecdhPubKeyBase64), c => c.charCodeAt(0));
        const hash = await crypto.subtle.digest('SHA-256', rawKey);
        const view = new DataView(hash);

        let emojis = [];
        for (let i = 0; i < 4; i++) {
            const num = view.getUint8(i) % 64;
            emojis.push(OOB.EMOJIS[num]);
        }
        return emojis.join(' ');
    }
}
class WebRTC {
    static config = {
        iceServers: [
            { urls: "stun:e2ee.rany.ing:3478" },
            // ✅ 修复1：手机流量必备，添加 UDP+TCP 双协议 TURN
            { urls: "turn:e2ee.rany.ing:3478?transport=udp", username: "e2ee", credential: "123456" },
            { urls: "turn:e2ee.rany.ing:3478?transport=tcp", username: "e2ee", credential: "123456" }
        ]
    };
    static callerUserID = null;
    static callerPC = null;
    static callerChannel = null;
    static calleeUserID = null;
    static calleePC = null;
    static calleeChannel = null;

    // ✅ 修复2：添加 ICE 候选缓存队列（解决iOS时序问题）
    static iceCandidateQueue = { caller: [], callee: [] };

    // 🔥 iOS 强制必备：申请媒体权限
    static async requestiOSMediaPermission() {
        try {
            await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            console.log("✅ 媒体权限获取成功");
        } catch (e) {
            console.error("❌ 权限获取失败", e);
        }
    }

    static getPCStatus = async (pc) => {
        if (!pc) return "❌ 无连接";

        try {
            const stats = await pc.getStats();
            let selectedPair;

            // 遍历查找已选中的线路
            for (const stat of stats.values()) {
                if (stat.type === "candidate-pair" && stat.nominated && stat.state === "succeeded") {
                    selectedPair = stat;
                    break;
                }
            }

            // 🔥 核心修复：iOS 内核统计延迟，等待100ms重新获取一次
            if (!selectedPair) {
                await new Promise(r => setTimeout(r, 100));
                const stats2 = await pc.getStats();
                for (const stat of stats2.values()) {
                    if (stat.type === "candidate-pair" && stat.nominated && stat.state === "succeeded") {
                        selectedPair = stat;
                        break;
                    }
                }
            }

            // 最终仍未找到，返回通用连接成功
            if (!selectedPair) return "✅ соединение";

            // 获取真实线路类型
            const realCandidate = stats.get(selectedPair.localCandidateId);
            const typeMap = {
                host: "✅ Прямое локальное соединение (host)",
                srflx: "✅ STUN P2P прямое соединение",
                relay: "✅ TURN ретрансляция"
            };

            return typeMap[realCandidate.candidateType] || "✅ соединение";
        } catch (e) {
            return "❌ 获取失败";
        }
    };

    // ========== A 发起方 ==========
    static createPeerConnection = async (targetUserID) => {
        // ✅ 自动调用权限（全平台必备）
        // await WebRTC.requestiOSMediaPermission();

        WebRTC.callerPC = new RTCPeerConnection(WebRTC.config);

        WebRTC.callerChannel = WebRTC.callerPC.createDataChannel("chat");
        WebRTC.callerChannel.onmessage = (e) => {
            WebRTC.receiveOriginMessage(e);
        };
        WebRTC.callerChannel.onopen = async () => { };

        WebRTC.callerPC.onconnectionstatechange = async () => {
            if (WebRTC.callerPC.connectionState === "connected") {
                let type = await WebRTC.getPCStatus(WebRTC.callerPC);
                console.log("Caller 连接成功！类型：", type);
                document.getElementById("WebRTCType").innerHTML = type
            }
        };

        WebRTC.callerPC.onicecandidate = (event) => {
            if (event.candidate) {
                WS.send({
                    type: "WebRTCice",
                    targetUser: targetUserID,
                    candidate: event.candidate
                });
            }
        };

        const offer = await WebRTC.callerPC.createOffer();
        await WebRTC.callerPC.setLocalDescription(offer);
        return offer;
    };

    // ========== B 接收方 ==========
    static receivePeerConnection = async (offer, sourceUserID) => {
        // await WebRTC.requestiOSMediaPermission();

        WebRTC.calleePC = new RTCPeerConnection(WebRTC.config);

        WebRTC.calleePC.ondatachannel = (e) => {
            WebRTC.calleeChannel = e.channel;
            WebRTC.calleeChannel.onmessage = (e) => {
                WebRTC.receiveOriginMessage(e);
            };
            WebRTC.calleeChannel.onopen = async () => { };
        };

        WebRTC.calleePC.onconnectionstatechange = async () => {
            if (WebRTC.calleePC.connectionState === "connected") {
                let type = await WebRTC.getPCStatus(WebRTC.calleePC);
                console.log("Callee 连接成功！类型：", type);
                document.getElementById("WebRTCType").innerHTML = type
            }
        };

        WebRTC.calleePC.onicecandidate = (event) => {
            if (event.candidate) {
                WS.send({
                    type: "WebRTCice",
                    targetUser: sourceUserID,
                    candidate: event.candidate
                });
            }
        };

        await WebRTC.calleePC.setRemoteDescription(offer);
        // ✅ 设置完远端描述，刷新缓存的ICE候选
        WebRTC.flushIceCandidates("callee");

        const answer = await WebRTC.calleePC.createAnswer();
        await WebRTC.calleePC.setLocalDescription(answer);
        return answer;
    };

    // ========== A 设置 Answer ==========
    static setAnswerPeerConnection = async (answer) => {
        await WebRTC.callerPC.setRemoteDescription(answer);
        // ✅ 设置完Answer，刷新缓存的ICE候选
        WebRTC.flushIceCandidates("caller");
    };

    // ========== 安全发送消息 ==========
    static sendOriginMessage = async (message) => {
        return new Promise((resolve, reject) => {
            let channel;
            if (WebRTC.callerChannel) channel = WebRTC.callerChannel;
            if (WebRTC.calleeChannel) channel = WebRTC.calleeChannel;

            if (channel && channel.readyState === 'open') {
                channel.send(message);
                let originPanel = document.getElementById("originMessagePanel");
                let text1 = document.createTextNode(`Me: ${message}`);
                originPanel.appendChild(text1);
                originPanel.appendChild(document.createElement("br"));
                resolve();
            } else {
                console.warn("⚠️ 通道未打开！");
                reject("⚠️ 通道未打开！");
            }
        })
    };

    static sendEncryptedMessage = async (message) => {
        const encryptedMessage = await CryptoUtils.encryptWithPeerPubKey(
            WS.ecdhPrivateKey,
            WS.otherecdhPubKey,
            message
        );

        let answer = JSON.stringify({
            type: "encryptedMessage",
            encryptedMessage,
        })
        await WebRTC.sendOriginMessage(answer);

        let encPanel = document.getElementById("encryptedMessagePanel");
        let text2 = document.createTextNode(`Me: ${message}`);
        encPanel.appendChild(text2);
        encPanel.appendChild(document.createElement("br"));
    }

    static receiveOriginMessage = async (e) => {
        try {
            let answer = JSON.parse(e.data);
            switch (answer.type) {
                case "encryptedMessage":
                    let originPanel = document.getElementById("originMessagePanel");
                    let text1 = document.createTextNode(`${WS.targetUser}: ${e.data}`);
                    originPanel.appendChild(text1);
                    originPanel.appendChild(document.createElement("br"));

                    let decryptedMsg = await CryptoUtils.decryptWithPrivateKey(
                        WS.ecdhPrivateKey,
                        WS.otherecdhPubKey,
                        answer.encryptedMessage
                    );

                    let encPanel = document.getElementById("encryptedMessagePanel");
                    let text2 = document.createTextNode(`${WS.targetUser}: ${decryptedMsg}`);
                    encPanel.appendChild(text2);
                    encPanel.appendChild(document.createElement("br"));
                    break;
                default:
                    throw Error();
            }
        } catch (ex) {
            let originPanel = document.getElementById("originMessagePanel");
            let text = document.createTextNode(`${WS.targetUser}: ${e.data}`);
            originPanel.appendChild(text);
            originPanel.appendChild(document.createElement("br"));
        }
    }

    // ========== ✅ 修复3：带缓存的 ICE 候选添加 ==========
    static addIceCandidate = async (candidate) => {
        const isCaller = !!WebRTC.callerPC;
        const pc = WebRTC.callerPC || WebRTC.calleePC;
        const type = isCaller ? "caller" : "callee";

        // 如果连接未准备好，缓存候选
        if (!pc || !pc.remoteDescription) {
            WebRTC.iceCandidateQueue[type].push(candidate);
            console.log("⏳ ICE 候选已缓存");
            return;
        }

        try {
            await pc.addIceCandidate(new RTCIceCandidate(candidate));
            console.log("✅ ICE 候选添加成功");
        } catch (e) {
            console.error("❌ ICE 添加失败", e);
        }
    };

    // ✅ 修复4：清空缓存的 ICE 候选
    static flushIceCandidates = (type) => {
        const pc = type === "caller" ? WebRTC.callerPC : WebRTC.calleePC;
        if (!pc) return;

        const queue = WebRTC.iceCandidateQueue[type];
        while (queue.length) {
            const candidate = queue.shift();
            pc.addIceCandidate(new RTCIceCandidate(candidate)).catch(console.error);
        }
    };
}

/**
 * 浏览器密钥存储工具（安全存储ECDSA/ECDH密钥对）
 * 核心：私钥加密后存localStorage，公钥明文存储
 */
class KeyStorage {


    static keyPairs = null;
    // 存储密钥的前缀（避免冲突）
    static STORAGE_PREFIX = 'e2ee_keypair_';

    /**
     * 加密私钥（用于localStorage存储，防止明文泄露）
     * @param {CryptoKey} privateKey - 原始私钥对象
     * @param {string} password - 用户密码/随机密钥（建议至少8位）
     * @returns {Promise<string>} 加密后的Base64字符串
     */
    static async encryptPrivateKey(privateKey, password) {
        // 1. 导出私钥为JWK格式（可序列化）
        const jwk = await crypto.subtle.exportKey('jwk', privateKey);
        const jwkStr = JSON.stringify(jwk);

        // 2. 用密码生成加密密钥（AES-GCM）
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        const encryptKey = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: encoder.encode('e2ee_salt_123'), iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        // 3. 加密JWK字符串
        const iv = crypto.getRandomValues(new Uint8Array(12)); // GCM随机IV
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            encryptKey,
            encoder.encode(jwkStr)
        );

        // 4. 拼接IV+密文，转Base64存储
        const combined = new Uint8Array([...iv, ...new Uint8Array(encrypted)]);
        return btoa(String.fromCharCode(...combined));
    }

    /**
     * 解密私钥（从localStorage读取后还原）
     * @param {string} encryptedBase64 - 加密后的Base64字符串
     * @param {string} password - 加密时的密码
     * @param {string} keyType - 密钥类型（ECDSA/ECDH）
     * @returns {Promise<CryptoKey>} 还原后的私钥对象
     */
    static async decryptPrivateKey(encryptedBase64, password, keyType) {
        try {
            // 1. 解码Base64，拆分IV+密文
            const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            const iv = combined.slice(0, 12);
            const ciphertext = combined.slice(12);

            // 2. 还原加密密钥
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            const decryptKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: encoder.encode('e2ee_salt_123'), iterations: 100000, hash: 'SHA-256' },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );

            // 3. 解密密文，还原JWK
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                decryptKey,
                ciphertext
            );
            const jwkStr = new TextDecoder().decode(decrypted);
            const jwk = JSON.parse(jwkStr);

            // 4. 导入JWK为原始私钥对象
            const algo = keyType === 'ECDSA'
                ? { name: 'ECDSA', namedCurve: 'P-256' }
                : { name: 'ECDH', namedCurve: 'P-256' };
            return crypto.subtle.importKey(
                'jwk',
                jwk,
                algo,
                false,
                keyType === 'ECDSA' ? ['sign'] : ['deriveKey']
            );
        } catch (err) {
            console.error('解密私钥失败：', err);
            throw new Error('密码错误或密钥损坏');
        }
    }

    /**
     * 存储密钥对到localStorage
     * @param {Object} keyPairs - 生成的密钥对（包含ecdsaPrivateKey/ecdhPrivateKey/公钥）
     * @param {string} userId - 用户ID（作为存储key）
     * @param {string} password - 加密私钥的密码
     * @returns {Promise<void>}
     */
    static async saveKeyPairs(keyPairs, userId, password) {
        // 1. 加密ECDSA私钥
        const encryptedEcdsaPrivate = await this.encryptPrivateKey(keyPairs.ecdsaPrivateKey, password);
        // 2. 加密ECDH私钥
        const encryptedEcdhPrivate = await this.encryptPrivateKey(keyPairs.ecdhPrivateKey, password);

        // 3. 组装存储对象（公钥明文，私钥加密）
        const storageObj = {
            userId,
            ecdsaPubKey: keyPairs.ecdsaPubKey,
            ecdhPubKey: keyPairs.ecdhPubKey,
            encryptedEcdsaPrivate,
            encryptedEcdhPrivate,
            createTime: new Date().toISOString()
        };

        // 4. 存储到localStorage
        localStorage.setItem(this.STORAGE_PREFIX + userId, JSON.stringify(storageObj));
        console.log('密钥对已存储到localStorage，用户ID：', userId);
    }

    /**
     * 从localStorage读取并还原密钥对
     * @param {string} userId - 用户ID
     * @param {string} password - 解密私钥的密码
     * @returns {Promise<Object>} 还原后的密钥对（包含原始CryptoKey对象）
     */
    static async loadKeyPairs(userId, password) {
        // 1. 读取localStorage
        const storageStr = localStorage.getItem(this.STORAGE_PREFIX + userId);
        if (!storageStr) {
            throw new Error(`未找到用户${userId}的密钥对`);
        }
        const storageObj = JSON.parse(storageStr);

        // 2. 解密私钥
        const ecdsaPrivateKey = await this.decryptPrivateKey(storageObj.encryptedEcdsaPrivate, password, 'ECDSA');
        const ecdhPrivateKey = await this.decryptPrivateKey(storageObj.encryptedEcdhPrivate, password, 'ECDH');

        // 3. 还原完整密钥对
        return {
            ecdsaPubKey: storageObj.ecdsaPubKey,
            ecdsaPrivateKey,
            ecdhPubKey: storageObj.ecdhPubKey,
            ecdhPrivateKey,
            userID: storageObj.userId
        };
    }

    /**
     * 删除指定用户的密钥对
     * @param {string} userId - 用户ID
     */
    static deleteKeyPairs(userId) {
        localStorage.removeItem(this.STORAGE_PREFIX + userId);
        console.log('密钥对已删除，用户ID：', userId);
    }

    /**
     * 检查用户是否有已存储的密钥对
     * @param {string} userId - 用户ID
     * @returns {boolean}
     */
    static hasKeyPairs(userId) {
        return !!localStorage.getItem(this.STORAGE_PREFIX + userId);
    }

    static getLocalStorageUserKeys() {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            // 跳过 null/undefined（极端情况）
            if (!key) continue;
            // 按前缀过滤
            if (this.STORAGE_PREFIX && !key.startsWith(this.STORAGE_PREFIX)) continue;
            keys.push(key);
        }
        return keys;
    }
}

// 初始化连接（必须调用一次）
WS.openWS();
setInterval(() => {
    document.getElementById("serverStatus").style.color = WS.WSStatus ? "green" : "red";
}, 100)
let newUser = () => {
    WS.newUser();
}
let loadUser = () => {
    WS.loadUser();
}
let getOnlineUsersList = () => {
    WS.getOnlineUsersList();
}
let connectTargetUser = () => {
    WS.connectTargetUser();
}
let sendOriginMessage = () => {
    let message = document.getElementById("originMessage").value;
    WebRTC.sendOriginMessage(message);
}
let sendEncryptedMessage = () => {
    let message = document.getElementById("encryptedMessage").value;
    WebRTC.sendEncryptedMessage(message)
}
let iamphone = () => {
    WebRTC.requestiOSMediaPermission();
}
window.onload = () => {
    loadOperatorUser();
}
//////////////////WS

let loadOperatorUser = () => {
    let keys = KeyStorage.getLocalStorageUserKeys();

    // 3. 核心：将 keys 转换为 {value, label} 格式（forEach 实现）
    const optionData = [];
    keys.forEach(key => {
        // 截断前缀，获取纯用户ID
        const userId = key.replace(KeyStorage.STORAGE_PREFIX, '');

        // 填充选项格式
        optionData.push({
            value: key, // 选中时的取值（如 user_20700）
            label: `${userId}` // 页面显示的文本
        });
    });
    renderRadioList("operatorUser", optionData, bindOperatorUserChangeEvent);
}

function renderRadioList(containerId, options, bindRadioChangeEvent) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.error('容器不存在：', containerId);
        return;
    }

    // 清空容器（避免重复填充）
    container.innerHTML = '';

    // 去重：确保同一value只生成一个单选框（可选，根据业务需求）
    const uniqueOptions = Array.from(new Map(options.map(item => [item.value, item])).values());

    // 遍历生成单选框
    uniqueOptions.forEach((option, index) => {
        // 1. 创建单选框DOM
        const radioInput = document.createElement('input');
        radioInput.type = 'radio';
        radioInput.name = `${containerId}Select`; // 同一组单选框name必须相同
        radioInput.id = `radio_${option.value}_${index}`; // 唯一ID（避免冲突）
        radioInput.value = option.value;
        // 设置默认选中
        // if (option.value === defaultSelected) {
        // if (index === 0) {
        //     radioInput.checked = true;
        // }

        // 2. 创建标签（关联单选框，点击文字也能选中）
        const radioLabel = document.createElement('label');
        radioLabel.htmlFor = radioInput.id;
        radioLabel.textContent = option.label;
        radioLabel.style.marginLeft = '8px';

        // 3. 包装单个选项
        const radioItem = document.createElement('div');
        radioItem.className = 'radio-item';
        radioItem.appendChild(radioInput);
        radioItem.appendChild(radioLabel);

        // 4. 添加到容器
        container.appendChild(radioItem);
    });

    // 监听选中状态变化
    switch (containerId) {
        case "operatorUser":
            bindRadioChangeEvent(`${containerId}Select`, 'selectedInfo');
            break;
        case "onlineUsersList":
            bindRadioChangeEvent(`${containerId}Select`, 'selectedInfo');
            break;
    }
}

/**
 * 步骤3：监听单选框选中状态变化
 * @param {string} radioName - 单选框组的name
 * @param {string} infoContainerId - 显示选中信息的容器ID
 */
function bindOperatorUserChangeEvent(radioName, infoContainerId) {
    const radioElements = document.querySelectorAll(`input[name="${radioName}"]`);
    const infoContainer = document.getElementById(infoContainerId);

    radioElements.forEach(radio => {
        radio.addEventListener('change', function () {
            if (this.checked) {
                // 这里可添加选中后的业务逻辑（如读取对应用户的密钥）
                const userID = this.value.replace(KeyStorage.STORAGE_PREFIX, '');

                console.log('选中的用户ID：', userID);
                // 2. 
                // document.getElementById('userID').textContent = userID;
                WS.userID = userID;
            }
        });
    });
}