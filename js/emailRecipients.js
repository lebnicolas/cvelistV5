/**
 * Gestion des destinataires email
 */

const EMAIL_RECIPIENTS = {
    recipients: [],
    
    /**
     * Charge les destinataires depuis le serveur
     */
    async loadRecipients() {
        try {
            const response = await fetch('/api/email-recipients');
            if (response.ok) {
                const data = await response.json();
                this.recipients = data.recipients || [];
                this.renderRecipients();
            } else {
                console.warn('Impossible de charger les destinataires, utilisation des valeurs par défaut');
                this.recipients = ['nicolas.lebon@atos.net'];
                this.renderRecipients();
            }
        } catch (error) {
            console.error('Erreur lors du chargement des destinataires:', error);
            // Valeurs par défaut en cas d'erreur
            this.recipients = ['nicolas.lebon@atos.net'];
            this.renderRecipients();
        }
    },
    
    /**
     * Ajoute un destinataire
     */
    async addRecipient(email) {
        const trimmedEmail = email.trim().toLowerCase();
        
        if (!trimmedEmail) {
            alert('L\'email ne peut pas être vide');
            return false;
        }
        
        // Validation basique de l'email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(trimmedEmail)) {
            alert('Format d\'email invalide');
            return false;
        }
        
        if (this.recipients.includes(trimmedEmail)) {
            alert(`L'email "${trimmedEmail}" est déjà dans la liste`);
            return false;
        }
        
        try {
            const response = await fetch('/api/email-recipients', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email: trimmedEmail })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: `Erreur HTTP ${response.status}` }));
                throw new Error(errorData.error || `Erreur HTTP ${response.status}`);
            }
            
            const result = await response.json();
            this.recipients = result.recipients || [];
            this.renderRecipients();
            console.log('Destinataire ajouté avec succès');
            return true;
        } catch (error) {
            console.error('Erreur lors de l\'ajout du destinataire:', error);
            alert(`Erreur lors de l'ajout du destinataire: ${error.message}`);
            return false;
        }
    },
    
    /**
     * Supprime un destinataire
     */
    async removeRecipient(email) {
        const index = this.recipients.indexOf(email);
        if (index > -1) {
            // Sauvegarder l'état actuel pour pouvoir le restaurer en cas d'erreur
            const previousRecipients = [...this.recipients];
            
            // Supprimer le destinataire
            this.recipients.splice(index, 1);
            this.renderRecipients();
            
            try {
                const response = await fetch(`/api/email-recipients?email=${encodeURIComponent(email)}`, {
                    method: 'DELETE'
                });
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: `Erreur HTTP ${response.status}` }));
                    throw new Error(errorData.error || `Erreur HTTP ${response.status}`);
                }
                
                const result = await response.json();
                this.recipients = result.recipients || [];
                this.renderRecipients();
                return true;
            } catch (error) {
                console.error('Erreur lors de la suppression du destinataire:', error);
                // Restaurer l'état précédent en cas d'erreur
                this.recipients = previousRecipients;
                this.renderRecipients();
                alert(`Erreur lors de la suppression du destinataire: ${error.message}`);
                return false;
            }
        }
        return false;
    },
    
    /**
     * Affiche la liste des destinataires dans le DOM
     */
    renderRecipients() {
        const container = document.getElementById('emailRecipientsList');
        if (!container) {
            return;
        }
        
        container.innerHTML = '';
        
        if (this.recipients.length === 0) {
            container.innerHTML = '<div class="no-recipients">Aucun destinataire configuré</div>';
            return;
        }
        
        this.recipients.forEach(email => {
            const recipientItem = document.createElement('div');
            recipientItem.className = 'email-recipient-item';
            recipientItem.innerHTML = `
                <span class="email-recipient-email">${this.escapeHtml(email)}</span>
                <button class="remove-recipient-btn" data-email="${this.escapeHtml(email)}" title="Supprimer ce destinataire">×</button>
            `;
            container.appendChild(recipientItem);
        });
        
        // Attacher les event listeners pour les boutons de suppression
        container.querySelectorAll('.remove-recipient-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const email = e.target.getAttribute('data-email');
                if (confirm(`Voulez-vous supprimer le destinataire "${email}" ?`)) {
                    await this.removeRecipient(email);
                }
            });
        });
    },
    
    /**
     * Échappe les caractères HTML pour éviter les injections XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    /**
     * Envoie l'email avec les nouvelles CVE
     */
    async sendEmail() {
        const sendBtn = document.getElementById('sendEmailBtn');
        if (sendBtn) {
            sendBtn.disabled = true;
            sendBtn.textContent = 'Envoi en cours...';
        }
        
        try {
            const response = await fetch('/api/send-cve-email', {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                if (result.newCVEsCount > 0) {
                    alert(`Email envoyé avec succès !\n${result.newCVEsCount} nouvelle(s) CVE envoyée(s) à ${result.recipients?.join(', ') || 'les destinataires'}`);
                } else {
                    alert('Aucune nouvelle CVE à envoyer.');
                }
            } else {
                alert(`Erreur lors de l'envoi de l'email: ${result.message}`);
            }
        } catch (error) {
            console.error('Erreur lors de l\'envoi de l\'email:', error);
            alert(`Erreur lors de l'envoi de l'email: ${error.message}`);
        } finally {
            if (sendBtn) {
                sendBtn.disabled = false;
                sendBtn.textContent = '📧 Envoyer l\'email';
            }
        }
    },
    
    /**
     * Initialise le module
     */
    async init() {
        // Event listener pour le bouton d'ajout
        const addBtn = document.getElementById('addRecipientBtn');
        if (addBtn) {
            addBtn.addEventListener('click', () => {
                const email = prompt('Entrez l\'adresse email du nouveau destinataire:');
                if (email) {
                    this.addRecipient(email);
                }
            });
        }
        
        // Event listener pour le bouton d'envoi d'email
        const sendBtn = document.getElementById('sendEmailBtn');
        if (sendBtn) {
            sendBtn.addEventListener('click', () => {
                if (confirm('Voulez-vous envoyer l\'email avec les nouvelles CVE à tous les destinataires ?')) {
                    this.sendEmail();
                }
            });
        }
        
        // Charger les destinataires au démarrage
        await this.loadRecipients();
    }
};

// Initialiser au chargement de la page
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        EMAIL_RECIPIENTS.init();
    });
} else {
    EMAIL_RECIPIENTS.init();
}

