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

Un fichier `.env.example` est fourni à la racine du projet : il liste toutes les variables d'environnement requises avec des commentaires explicatifs.

### Étape 1 — Copier le template

```powershell
Copy-Item .env.example .env
```

### Étape 2 — Remplir les valeurs réelles

Édite le fichier `.env` ainsi créé et remplis :

```env
# Base de données PostgreSQL
DB_NAME=cveye_db
DB_USER=postgres
DB_PASSWORD=ton_mot_de_passe_postgres
DB_HOST=127.0.0.1
DB_PORT=5432

# Sécurité Django
DJANGO_SECRET_KEY=remplacer_par_une_cle_aleatoire
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
```

### Étape 3 — Générer une SECRET_KEY aléatoire

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Copie la sortie dans la variable `DJANGO_SECRET_KEY` du `.env`.

> ⚠️ Ce fichier `.env` ne doit **jamais** être committé sur SVN. Seul `.env.example` (sans secrets) est versionné.

> 🚀 **Sur le serveur de production**, mettre `DJANGO_DEBUG=False` et adapter `DJANGO_ALLOWED_HOSTS` aux vrais domaines (ex. `cveye.ovh,www.cveye.ovh`).


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

##  Lancer les tests

Le projet contient une suite de tests unitaires couvrant la validation des cibles, le scanner réseau, la corrélation CVE, l'authentification et le système de ban d'IP.

### Lancer tous les tests

```bash
python manage.py test
```

### Lancer les tests d'une seule app

```bash
python manage.py test app_core            # tests sur Cible / Scan / Service
python manage.py test app_scan            # tests sur SocketScanner et CPE
python manage.py test app_security        # tests sur NVDClient
python manage.py test app_dashboard       # tests sur risk_utils et la page Vulnérabilités
python manage.py test app_accounts        # tests sur l'authentification et le ban d'IP
```

### Mode verbeux (affiche le nom et la docstring de chaque test)

```bash
python manage.py test --verbosity 2
```

> 📋 Tous les tests doivent être verts avant de pousser un commit. Si un test échoue, corrige le bug ou adapte le test avant de committer.

---

##  Données de test (seed)

Pour développer ou tester l'interface sans avoir à scanner de vraies machines, le projet inclut un script qui peuple ta BD locale avec **8 cibles fictives** couvrant tous les cas d'affichage de la page Vulnérabilités.

### Lancer le seed

```bash
python seed_data.py
```

### Cas générés

| # | Cible | Cas testé |
|---|-------|-----------|
| 1 | 10.0.0.1 | Jamais scannée |
| 2 | 10.0.0.2 | Scan complet, 0 CVE |
| 3 | 10.0.0.3 | 2 CVE Faibles |
| 4 | 10.0.0.4 | 2 Moyennes + 1 Faible |
| 5 | 10.0.0.5 | 2 Élevées + 1 Moyenne |
| 6 | 10.0.0.6 | 2 Critiques + 1 Élevée + 1 Faible |
| 7 | 10.0.0.7 | Hors ligne (server_hs) |
| 8 | test.exemple.fr | Domaine, 2 Critiques + 1 Élevée + 1 Moyenne |

**Total** : 16 vulnérabilités, 9 services, 8 cibles attribuées au superuser local.

> ♻️ Le script est **idempotent** : tu peux le relancer plusieurs fois sans dupliquer les données. Il supprime ses propres entrées (reconnaissables au préfixe `[SEED]` dans la description) avant de les recréer.

> ⚠️ Pré-requis : un superuser doit exister dans la BD (`python manage.py createsuperuser`). Les cibles seront attribuées à ce superuser.

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

