# Modèle CIA (Confidentialité – Intégrité – Disponibilité)

### 1. Confidentialité

* **Définition** : Protection des données contre tout accès non autorisé.
* **Menaces** :

  * Piratage de bases de données (ex. vol d’identifiants).
  * Interception de communications non chiffrées (attaque Man-in-the-Middle).
  * Mauvaise configuration des permissions (partage public de fichiers sensibles).
* **Exemple concret** : Une application Django qui expose la base SQLite sur le web → n’importe qui peut télécharger les données.
* **Mesures de protection** :

  * Authentification forte (MFA, mots de passe robustes).
  * Chiffrement des données sensibles (AES-256 au repos, TLS 1.3 en transit).
  * Gestion fine des accès (RBAC, groupes, ACL).

---

### 2. Intégrité

* **Définition** : Assurer que les données ne sont ni altérées ni corrompues de manière non autorisée.
* **Menaces** :

  * Injection SQL modifiant ou supprimant des données.
  * Modification de fichiers logs ou systèmes par un attaquant.
  * Malware altérant des fichiers de configuration.
* **Exemple concret** : Un utilisateur malveillant qui injecte du SQL dans un champ de formulaire pour supprimer des tables.
* **Mesures de protection** :

  * Signatures numériques, hash (SHA-256, HMAC).
  * ORM Django pour prévenir l’injection SQL.
  * Sauvegardes régulières et contrôles d’intégrité (checksums).

---

### 3. Disponibilité

* **Définition** : Garantir que les systèmes et services restent accessibles aux utilisateurs autorisés.
* **Menaces** :

  * Attaques DDoS saturant le serveur.
  * Pannes matérielles ou réseau.
  * Sinistres physiques (incendie, inondation).
* **Exemple concret** : Un serveur Django indisponible à cause d’une attaque DDoS sur le port 80.
* **Mesures de protection** :

  * Redondance (clusters, load balancers).
  * PRA/PCA (plan de reprise d’activité / plan de continuité).
  * Outils anti-DDoS et monitoring proactif (Zabbix, Grafana, WAF).

---

# OWASP Top 10 – Menaces pour les applications web

### A01 – Broken Access Control

* **Définition** : Défauts dans la gestion des autorisations.
* **Exemple** : Un utilisateur standard accède à `/admin/delete_user` sans droit.
* **Menace** : Accès non autorisé, modification de données sensibles.
* **Mesures** : Vérification stricte côté serveur, principe du moindre privilège, tests d’autorisation automatisés.

---

### A02 – Cryptographic Failures

* **Définition** : Données sensibles mal protégées ou non chiffrées.
* **Exemple** : Mots de passe stockés en clair dans la base de données.
* **Menace** : Fuite d’informations sensibles en cas d’attaque.
* **Mesures** : Chiffrement TLS en transit, AES-256 au repos, hashage PBKDF2/Argon2/BCrypt pour les mots de passe.

---

### A03 – Injection (SQL, NoSQL, LDAP, OS Command)

* **Définition** : Entrées utilisateur mal contrôlées qui deviennent du code exécutable.
* **Exemple** : `SELECT * FROM users WHERE name = 'admin' OR '1'='1';`
* **Menace** : Lecture, modification ou suppression des données.
* **Mesures** : ORM Django, requêtes paramétrées, validation stricte des entrées.

---

### A04 – Insecure Design

* **Définition** : Erreurs de conception dans l’architecture logicielle.
* **Exemple** : Application qui n’impose pas de mot de passe fort.
* **Menace** : Failles difficiles à corriger après coup.
* **Mesures** : Secure by Design, threat modeling, revue de conception de sécurité.

---

### A05 – Security Misconfiguration

* **Définition** : Paramètres ou environnements mal configurés.
* **Exemple** : Django déployé avec `DEBUG=True` en production.
* **Menace** : Exposition d’informations sensibles, accès non désiré.
* **Mesures** : Revue régulière, automatisation des configurations (Ansible, Docker), durcissement du système.

---

### A06 – Vulnerable and Outdated Components

* **Définition** : Utilisation de composants vulnérables ou non mis à jour.
* **Exemple** : Utiliser une version ancienne de Django avec une faille critique (CVE).
* **Menace** : Exploitation via vulnérabilité connue (CVE publique).
* **Mesures** : Mises à jour fréquentes, scans automatiques (`pip-audit`, `safety`).

---

### A07 – Identification and Authentication Failures

* **Définition** : Gestion faible de l’authentification et des sessions.
* **Exemple** : Connexion sans limitation → brute force possible.
* **Menace** : Usurpation d’identité, accès frauduleux.
* **Mesures** : MFA/2FA, verrouillage après X tentatives, expiration automatique des sessions.

---

### A08 – Software and Data Integrity Failures

* **Définition** : Absence de validation d’intégrité du code ou des données.
* **Exemple** : Installer une librairie Python corrompue depuis un dépôt non officiel.
* **Menace** : Exécution de code malveillant dans l’application.
* **Mesures** : Vérification des signatures, dépôts fiables, contrôles d’intégrité.

---

### A09 – Security Logging and Monitoring Failures

* **Définition** : Mauvaise gestion des logs et absence de surveillance.
* **Exemple** : Tentatives d’attaque non détectées car les logs sont désactivés.
* **Menace** : Intrusions indétectables, perte de visibilité.
* **Mesures** : Centralisation des logs, SIEM (Wazuh, ELK), alertes automatiques.

---

### A10 – Server-Side Request Forgery (SSRF)

* **Définition** : Attaquant qui force le serveur à envoyer des requêtes à d’autres systèmes.
* **Exemple** : Utiliser une API vulnérable pour accéder à `http://127.0.0.1:8080/admin`.
* **Menace** : Exfiltration de données internes, pivot vers d’autres systèmes.
* **Mesures** : Restreindre les requêtes sortantes, validation des entrées, listes blanches d’URLs autorisées.

---

👉 Veux-tu que je crée un **tableau comparatif (CIA vs OWASP Top 10)** avec **Objectif – Menace – Exemple – Mesures**, qui serait directement exploitable dans une slide Canva ?
