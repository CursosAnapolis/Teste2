class AuthSystem {
    constructor() {
        this.users = {
            'erikslava': {
                password: '55676209-1',
                webhook: '',
                isAdmin: false,
                profilePic: ''
            },
            'ynn': {
                password: 'gabrielomned',
                webhook: '',
                isAdmin: false,
                profilePic: ''
            },
            'erikAdmin': {
                password: 'rasgada333',
                webhook: '',
                isAdmin: true,
                profilePic: ''
            }
        };
        
        this.failedAttempts = {};
        this.bannedIPs = {};
        this.webhookURL = "https://discord.com/api/webhooks/1429236562134302781/9aDDtdDEO18AtU_Z7s08oRx9vjwhaez9shQWO6P3Ycf0ljNPM5iEitEd1f_8p8Opj-o2";
        this.verificationCodes = {};
        this.userWebhooks = {};
        
        this.init();
    }
    
    init() {
        this.loadFromStorage();
        this.setupEventListeners();
        this.checkBanStatus();
    }
    
    loadFromStorage() {
        const storedUsers = localStorage.getItem('chatUsers');
        if (storedUsers) {
            this.users = JSON.parse(storedUsers);
        }
        
        const storedFailed = localStorage.getItem('failedAttempts');
        if (storedFailed) {
            this.failedAttempts = JSON.parse(storedFailed);
        }
        
        const storedBans = localStorage.getItem('bannedIPs');
        if (storedBans) {
            this.bannedIPs = JSON.parse(storedBans);
        }
        
        const storedWebhooks = localStorage.getItem('userWebhooks');
        if (storedWebhooks) {
            this.userWebhooks = JSON.parse(storedWebhooks);
        }
    }
    
    saveToStorage() {
        localStorage.setItem('chatUsers', JSON.stringify(this.users));
        localStorage.setItem('failedAttempts', JSON.stringify(this.failedAttempts));
        localStorage.setItem('bannedIPs', JSON.stringify(this.bannedIPs));
        localStorage.setItem('userWebhooks', JSON.stringify(this.userWebhooks));
    }
    
    async getIPInfo() {
        try {
            const response = await fetch('https://ipapi.co/json/');
            const data = await response.json();
            return {
                ip: data.ip,
                city: data.city,
                region: data.region,
                country: data.country_name,
                postal: data.postal,
                org: data.org,
                timezone: data.timezone,
                userAgent: navigator.userAgent,
                platform: navigator.platform
            };
        } catch (error) {
            return {
                ip: 'Unknown',
                userAgent: navigator.userAgent,
                platform: navigator.platform
            };
        }
    }
    
    async sendWebhook(data) {
        const embed = {
            title: data.title || 'Chat Sangue - Log',
            color: 0x8B0000,
            fields: [],
            timestamp: new Date().toISOString(),
            footer: {
                text: 'Chat Sangue Security System'
            }
        };
        
        if (data.user) {
            embed.fields.push({ name: 'Usuário', value: data.user, inline: true });
        }
        
        if (data.action) {
            embed.fields.push({ name: 'Ação', value: data.action, inline: true });
        }
        
        if (data.ipInfo) {
            embed.fields.push({ name: 'IP', value: data.ipInfo.ip || 'Unknown', inline: true });
            embed.fields.push({ name: 'Localização', value: `${data.ipInfo.city || 'Unknown'}, ${data.ipInfo.country || 'Unknown'}`, inline: true });
            embed.fields.push({ name: 'ISP', value: data.ipInfo.org || 'Unknown', inline: false });
        }
        
        if (data.details) {
            embed.fields.push({ name: 'Detalhes', value: data.details, inline: false });
        }
        
        const payload = {
            embeds: [embed],
            username: 'Chat Sangue Security',
            avatar_url: 'https://i.imgur.com/xxx.png' // Add blood drop icon
        };
        
        try {
            await fetch(this.webhookURL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (error) {
            console.error('Webhook error:', error);
        }
    }
    
    generateVerificationCode() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }
    
    async login(username, password) {
        const ipInfo = await this.getIPInfo();
        const ip = ipInfo.ip;
        
        // Check if IP is banned
        if (this.bannedIPs[ip] && this.bannedIPs[ip] > Date.now()) {
            this.showBanMessage(ip);
            return { success: false, reason: 'banned' };
        }
        
        if (!this.users[username]) {
            this.recordFailedAttempt(ip);
            await this.sendWebhook({
                title: 'Tentativa de Login Falha',
                user: username,
                action: 'Usuário não existe',
                ipInfo: ipInfo,
                details: `Tentativa com IP ${ip}`
            });
            return { success: false, reason: 'user_not_found' };
        }
        
        if (this.users[username].password !== password) {
            this.recordFailedAttempt(ip);
            await this.sendWebhook({
                title: 'Tentativa de Login Falha',
                user: username,
                action: 'Senha incorreta',
                ipInfo: ipInfo,
                details: `Tentativa ${this.failedAttempts[ip] || 1}`
            });
            return { success: false, reason: 'wrong_password' };
        }
        
        // Successful login
        delete this.failedAttempts[ip];
        this.saveToStorage();
        
        // Generate verification code
        const code = this.generateVerificationCode();
        this.verificationCodes[username] = code;
        
        // Send code via webhook (simulated)
        await this.sendWebhook({
            title: 'Código de Verificação',
            user: username,
            action: 'Login iniciado',
            ipInfo: ipInfo,
            details: `Código: ${code} (Simulado - Em produção enviar para webhook do usuário)`
        });
        
        return { 
            success: true, 
            requiresVerification: true,
            username: username,
            isAdmin: this.users[username].isAdmin
        };
    }
    
    verifyCode(username, code) {
        if (this.verificationCodes[username] === code) {
            delete this.verificationCodes[username];
            
            // Store session
            const sessionToken = this.generateSessionToken();
            localStorage.setItem('sessionToken', sessionToken);
            localStorage.setItem('currentUser', JSON.stringify({
                username: username,
                isAdmin: this.users[username].isAdmin,
                profilePic: this.users[username].profilePic,
                loginTime: Date.now()
            }));
            
            return { success: true, sessionToken: sessionToken };
        }
        return { success: false, reason: 'invalid_code' };
    }
    
    generateSessionToken() {
        return 'session_' + Math.random().toString(36).substr(2) + Date.now().toString(36);
    }
    
    recordFailedAttempt(ip) {
        if (!this.failedAttempts[ip]) {
            this.failedAttempts[ip] = 0;
        }
        this.failedAttempts[ip]++;
        
        const attempts = this.failedAttempts[ip];
        let banTime = 0;
        
        switch(attempts) {
            case 3: banTime = 1 * 60 * 1000; break; // 1 minuto
            case 4: banTime = 5 * 60 * 1000; break; // 5 minutos
            case 5: banTime = 10 * 60 * 1000; break; // 10 minutos
            case 6: banTime = 30 * 60 * 1000; break; // 30 minutos
            case 7: banTime = 60 * 60 * 1000; break; // 1 hora
            case 8: banTime = 24 * 60 * 60 * 1000; break; // 1 dia
            case 9: banTime = Number.MAX_SAFE_INTEGER; break; // Ban permanente
        }
        
        if (banTime > 0) {
            this.bannedIPs[ip] = Date.now() + banTime;
            this.saveToStorage();
            this.showBanMessage(ip);
        }
        
        this.saveToStorage();
    }
    
    showBanMessage(ip) {
        const banEnd = this.bannedIPs[ip];
        if (!banEnd) return;
        
        const timeLeft = banEnd - Date.now();
        let timeText = '';
        
        if (timeLeft === Number.MAX_SAFE_INTEGER) {
            timeText = 'PERMANENTE';
        } else if (timeLeft > 24 * 60 * 60 * 1000) {
            timeText = Math.ceil(timeLeft / (24 * 60 * 60 * 1000)) + ' dias';
        } else if (timeLeft > 60 * 60 * 1000) {
            timeText = Math.ceil(timeLeft / (60 * 60 * 1000)) + ' horas';
        } else if (timeLeft > 60 * 1000) {
            timeText = Math.ceil(timeLeft / (60 * 1000)) + ' minutos';
        } else {
            timeText = Math.ceil(timeLeft / 1000) + ' segundos';
        }
        
        const modal = document.getElementById('banModal');
        const banTimeEl = document.getElementById('banTime');
        
        if (modal && banTimeEl) {
            banTimeEl.textContent = timeText;
            modal.style.display = 'flex';
        }
    }
    
    checkBanStatus() {
        const ip = Object.keys(this.bannedIPs)[0]; // Simplified
        if (ip && this.bannedIPs[ip] > Date.now()) {
            this.showBanMessage(ip);
            return true;
        }
        return false;
    }
    
    addUser(username, password, webhook = '', isAdmin = false) {
        if (!this.isAdminLoggedIn()) {
            return { success: false, reason: 'not_authorized' };
        }
        
        this.users[username] = {
            password: password,
            webhook: webhook,
            isAdmin: isAdmin,
            profilePic: ''
        };
        
        this.saveToStorage();
        return { success: true };
    }
    
    removeUser(username) {
        if (!this.isAdminLoggedIn()) {
            return { success: false, reason: 'not_authorized' };
        }
        
        if (this.users[username]) {
            delete this.users[username];
            this.saveToStorage();
            return { success: true };
        }
        return { success: false, reason: 'user_not_found' };
    }
    
    updateUser(username, updates) {
        const user = this.users[username];
        if (!user) return { success: false, reason: 'user_not_found' };
        
        Object.assign(user, updates);
        this.saveToStorage();
        return { success: true };
    }
    
    isAdminLoggedIn() {
        const userData = localStorage.getItem('currentUser');
        if (!userData) return false;
        
        const user = JSON.parse(userData);
        return user.isAdmin === true;
    }
    
    getCurrentUser() {
        const userData = localStorage.getItem('currentUser');
        return userData ? JSON.parse(userData) : null;
    }
    
    logout() {
        localStorage.removeItem('sessionToken');
        localStorage.removeItem('currentUser');
    }
    
    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        // Password toggle
        const togglePassword = document.getElementById('togglePassword');
        if (togglePassword) {
            togglePassword.addEventListener('click', () => {
                const passwordInput = document.getElementById('password');
                const type = passwordInput.type === 'password' ? 'text' : 'password';
                passwordInput.type = type;
                togglePassword.classList.toggle('fa-eye');
                togglePassword.classList.toggle('fa-eye-slash');
            });
        }
        
        // Request access
        const requestLinks = document.querySelectorAll('#requestAccess, #requestAccessLink');
        requestLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                this.showRequestModal();
            });
        });
        
        // Request form
        const requestForm = document.getElementById('requestForm');
        if (requestForm) {
            requestForm.addEventListener('submit', (e) => this.handleRequestAccess(e));
        }
        
        // Close modals
        const closeButtons = document.querySelectorAll('.close');
        closeButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const modal = btn.closest('.modal');
                if (modal) modal.style.display = 'none';
            });
        });
        
        // Close modal on outside click
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
            }
        });
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const codeGroup = document.getElementById('codeGroup');
        const codeInput = document.getElementById('verificationCode');
        
        // If code group is visible, verify code
        if (codeGroup.style.display !== 'none') {
            const result = this.verifyCode(username, codeInput.value);
            if (result.success) {
                alert('Login bem-sucedido!');
                // Redirect based on user type
                const user = this.getCurrentUser();
                if (user.isAdmin) {
                    window.location.href = 'admin.html';
                } else {
                    window.location.href = 'chat.html';
                }
            } else {
                alert('Código inválido!');
            }
            return;
        }
        
        // Initial login
        const result = await this.login(username, password);
        
        if (result.success && result.requiresVerification) {
            codeGroup.style.display = 'block';
            alert('Código de verificação enviado (simulado). Use o console para ver o código.');
            console.log('Código de verificação:', this.verificationCodes[username]);
        } else if (result.success) {
            alert('Login bem-sucedido!');
            // Redirect based on user type
            if (result.isAdmin) {
                window.location.href = 'admin.html';
            } else {
                window.location.href = 'chat.html';
            }
        } else {
            alert('Usuário ou senha incorretos!');
        }
    }
    
    async handleRequestAccess(e) {
        e.preventDefault();
        
        const fullName = document.getElementById('fullName').value;
        const phoneEmail = document.getElementById('phoneEmail').value;
        const desiredUser = document.getElementById('desiredUser').value;
        const desiredPass = document.getElementById('desiredPass').value;
        const reason = document.getElementById('reason').value;
        
        const ipInfo = await this.getIPInfo();
        
        await this.sendWebhook({
            title: 'Nova Solicitação de Acesso',
            user: desiredUser,
            action: 'Solicitação enviada',
            ipInfo: ipInfo,
            details: `Nome: ${fullName}\nContato: ${phoneEmail}\nMotivo: ${reason}\n\nSenha desejada: ${desiredPass}`
        });
        
        alert('Solicitação enviada com sucesso! Você será contactado por e-mail/telefone.');
        
        const modal = document.getElementById('requestModal');
        if (modal) modal.style.display = 'none';
        
        // Reset form
        e.target.reset();
    }
    
    showRequestModal() {
        const modal = document.getElementById('requestModal');
        if (modal) modal.style.display = 'flex';
    }
}

// Initialize auth system
const auth = new AuthSystem();

// Export for other scripts
window.AuthSystem = auth;
