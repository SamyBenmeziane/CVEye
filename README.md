#  CVEye — Outil de Scan de Vulnérabilités

Projet universitaire L3 Informatique — Université Paris Cité

CVEye est une application web permettant :

- le scan de ports via sockets Python
- la détection de services et versions (analyse headers)
- la corrélation avec les CVE (NIST NVD API)
- l’affichage des résultats via une interface Django

---

##  Stack Technique

- Python 3.10+
- Django 4+
- PostgreSQL
- Bootstrap 5
- Scanner réseau basé sur sockets Python
- API NIST NVD 2.0

---

##  Structure du projet
trunk/
│
├── CVEye/ # configuration principale Django
├── app_dashboard/ # interface web (views + templates)
├── app_scan/ # scanner réseau (sockets)
├── app_security/ # corrélation CVE + notification mails
├── app_core/ #gestion (ajout, suppression, modification, etc) BD
├── manage.py
├── requirements.txt # dépendances à installer
└── README.md


##  Installation complète (Windows)

###  Cloner le dépôt SVN

```bash
svn checkout https://forge.ens.math-info.univ-paris5.fr/svn/2025-l3m2
```

Puis :

```bash
cd trunk
```

---

### 2️ Créer l’environnement virtuel Python

Dans le dossier du projet :

```bash
python -m venv venv
```

Activation :

```bash
venv\Scripts\activate
```

---

###  Installer les dépendances

```bash
pip install -r requirements.txt
```

---

##  Installation PostgreSQL

### Installer PostgreSQL

Télécharger :

https://www.postgresql.org/download/windows/

Pendant l’installation :

- garder le port `5432`
- retenir le mot de passe du user `postgres`

---

### Créer la base de données

Ouvrir pgAdmin ou psql (de préférence pgAdmin) :

Créer une base :
#### Créer la base
```
Databases --> Create --> Database 
Nom : cveye_db
```
#### Créer un user 
```
Login/Group Roles → Create → Login/Group Role
Name : cveye_user
Password : mettez un mot de passe (sans accents)
cochez : Can login
```
#### Donnez les droits (query tool) 
```
Sélectionne une DB (peu importe), puis Tools → Query Tool :

GRANT ALL PRIVILEGES ON DATABASE cveye_db TO cveye_user;
GRANT USAGE, CREATE ON SCHEMA public TO cveye_user;
ALTER SCHEMA public OWNER TO cveye_user;

Executez
```
---

##  Configuration environnement (.env)

Créer un fichier dans le dossier du projet, à côté de manage.py :

```bash
New-Item .env
@"
DB_NAME=cveye_db
DB_USER=cveye_user
DB_PASSWORD=TON_MDP
DB_HOST=127.0.0.1
DB_PORT=5432
"@ | Set-Content -Encoding utf8 .env
```
```
.env
```

Contenu :

```env
DB_NAME=cveye_db
DB_USER=postgres
DB_PASSWORD=YOUR_PASSWORD
DB_HOST=localhost
DB_PORT=5432
```

 Ce fichier ne doit **jamais** être commit.


---

##  Configuration Django (settings.py)

```python
import os

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST"),
        "PORT": os.getenv("DB_PORT"),
    }
}
```

---

##  Initialisation base de données

Créer les tables Django :

```bash
python manage.py migrate
```

---

##  Création administrateur Django

Chaque membre de l’équipe crée son propre admin local :

```bash
python manage.py createsuperuser
```

---

##  Lancer le serveur Django

```bash
python manage.py runserver 8888
```

Application :

```
http://127.0.0.1:8888
```

Admin :

```
http://127.0.0.1:8888/admin
```

---

##  Scanner réseau

Le scanner se trouve dans :

```
app_scan/scanner.py
```

Utilisation :

```python
scanner = UltimaScanner(target)
scanner.run()
results = scanner.results
```

---

##  Workflow équipe (SVN)

###  À COMMIT

- code Python
- templates HTML
- fichiers static (CSS/JS)
- migrations Django
- requirements.txt
- README.md

---

###  À NE PAS COMMIT

- venv/
- .env
- __pycache__/
- fichiers *.pyc
- base de données locale

---

##  Workflow conseillé

1. svn update
2. coder
3. tester localement
4. svn commit

---

##  Important (Base de données)

- Chaque développeur utilise sa propre base PostgreSQL locale.
- Les données ne sont pas partagées via SVN.
- Seules les migrations sont partagées.

---

##  Objectif final

Déploiement sur VPS sécurisé :

- Reverse proxy (Nginx)
- HTTPS
- Firewall
- Isolation scanner

---



##  Licence

Projet universitaire — usage pédagogique uniquement.

