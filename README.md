# Разработка кроссплатформенной системы end-to-end зашифрованной связи на основе каналов данных WebRTC

                Server
                   |
                   |
        -------------------------
        | SSL                   | SSL
        |                       |
     Client1-----------------Client2
            WebRTC, SSL

1. 新用户
client newUser
server replyNewUser userID
client uploadPublicKey userID ecdsaPubKey ecdhPubKey signature
server replyUploadPublicKey success userID

2. 加载用户
