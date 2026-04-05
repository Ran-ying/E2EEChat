cd /root
git clone https://github.com/Ran-ying/E2EEChat.git
cd E2EEChat
apt update
apt install nodejs npm -y
npm install
npm install -g pm2
pm2 start Server.js
pm2 startup
pm2 save

sudo nano /etc/nginx/sites-available/e2ee.rany.ing

```
server {
    listen 80;
    listen [::]:80;
    server_name e2ee.rany.ing;

    root /var/www/e2ee.rany.ing/html;
    index index.html index.htm;

    location / {
        proxy_pass https://127.0.0.1:4430;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

sudo ln -s /etc/nginx/sites-available/e2ee.rany.ing /etc/nginx/sites-enabled/
sudo nginx -t
sudo certbot --nginx -d e2ee.rany.ing
sudo systemctl restart nginx