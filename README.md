# CVEye – Outil de scan de vulnérabilités

Projet de L3 Informatique à l'Université Paris Cité (2025-2026), réalisé à 4 et encadré par M. Alaa Dandan.

CVEye est une application web qui permet de surveiller des serveurs et de repérer les failles connues sur les services qu'ils exposent. Concrètement, on ajoute une adresse IP ou un nom de domaine, on lance un scan, et l'application :

- teste les ports ouverts avec un scanner écrit en Python (sockets, sans nmap)
- identifie les services et leurs versions à partir des bannières et des en-têtes HTTP (HTTP, SSH, FTP)
- cherche les CVE correspondantes dans la base NVD du NIST
- affiche les résultats classés par gravité dans une interface Django

On peut aussi :

- faire une recherche manuelle de CVE sur plusieurs bases (NVD, CIRCL, OSV, Vulners)
- programmer des scans réguliers (toutes les heures, tous les jours, toutes les semaines ou tous les mois)
- générer un rapport PDF par cible
- recevoir un mail à la fin d'un scan programmé (serveur hors ligne, failles trouvées ou scan OK), avec le rapport en pièce jointe

Côté comptes, une inscription doit être confirmée par mail puis validée par un administrateur, et une adresse IP est bloquée après trois échecs de connexion.

L'application a été déployée sur un VPS (Nginx, Gunicorn, PostgreSQL, HTTPS avec Let's Encrypt).

> Projet pédagogique : à utiliser uniquement sur des machines que vous avez le droit de scanner.

---

## Stack technique

- Python 3.10+
- Django 6.0
- PostgreSQL
- Bootstrap 5
- ReportLab (rapports PDF)
- API NIST NVD 2.0, CIRCL, OSV, Vulners

---

## Structure du projet

```
CVEye/            configuration principale Django
app_accounts/     inscription, vérification mail, validation admin, ban d'IP
app_core/         modèles (cibles, scans, services) et commande des scans programmés
app_scan/         scanner réseau (sockets), exécution des scans, notifications mail
app_security/     corrélation CVE et clients NVD / CIRCL / OSV / Vulners
app_dashboard/    interface web, page vulnérabilités, rapports PDF
install.sh        script d'installation sur un serveur Debian/Ubuntu
manage.py
requirements.txt
```

---

## Installation en local (Windows)

### 1. Récupérer le projet

```bash
git clone https://github.com/SamyBenmeziane/CVEye.git
cd CVEye
```

Pendant le projet, l'équipe travaillait sur le SVN de la forge de l'université. Ce dépôt GitHub en est une copie.

### 2. Créer l'environnement virtuel

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

---

## PostgreSQL

### Installer PostgreSQL

Téléchargement : https://www.postgresql.org/download/windows/

Pendant l'installation, garder le port `5432` et noter le mot de passe de l'utilisateur `postgres`.

### Créer la base et l'utilisateur

Dans pgAdmin :

1. `Databases → Create → Database`, nom : `cveye_db`
2. `Login/Group Roles → Create → Login/Group Role`, nom : `cveye_user`, un mot de passe sans accents, et cocher `Can login`
3. Ouvrir `Tools → Query Tool` et exécuter :

```sql
GRANT ALL PRIVILEGES ON DATABASE cveye_db TO cveye_user;
GRANT USAGE, CREATE ON SCHEMA public TO cveye_user;
ALTER SCHEMA public OWNER TO cveye_user;
```

---

## Fichier .env

Les réglages sensibles ne sont pas dans le code. Il faut créer un fichier `.env` à la racine du projet :

```env
# Base de données
DB_NAME=cveye_db
DB_USER=cveye_user
DB_PASSWORD=votre_mot_de_passe
DB_HOST=127.0.0.1
DB_PORT=5432

# Django
DJANGO_SECRET_KEY=a_remplacer
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
```

Pour générer une `DJANGO_SECRET_KEY` :

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Le fichier `.env` ne doit jamais être versionné. En production, mettre `DJANGO_DEBUG=False` et indiquer les vrais domaines dans `DJANGO_ALLOWED_HOSTS`.

---

## Lancer l'application

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 8888
```

- Application : http://127.0.0.1:8888
- Admin Django : http://127.0.0.1:8888/admin

---

## Tests

46 tests unitaires couvrent la validation des cibles, le scanner, la corrélation CVE, la page vulnérabilités, l'authentification et le ban d'IP.

```bash
python manage.py test                  # tous les tests
python manage.py test app_core         # cibles, scans, services
python manage.py test app_scan         # scanner et construction des CPE
python manage.py test app_security     # client NVD
python manage.py test app_dashboard    # calcul du risque, page vulnérabilités
python manage.py test app_accounts     # authentification, ban d'IP
python manage.py test --verbosity 2    # affiche le détail de chaque test
```

---

## Scanner réseau

Le scanner se trouve dans `app_scan/scanner.py` :

```python
from app_scan.scanner import SocketScanner

scanner = SocketScanner("192.168.1.10")
scanner.run()
```

Par défaut, il teste les ports en parallèle avec un pool de threads. Le nombre de threads et la liste des ports peuvent être passés au constructeur (`max_threads`, `ports`).

---

## Scans programmés

La commande `run_scheduled_scans` lance les scans dont la date prévue est passée. Sur le serveur, elle est appelée par cron :

```bash
* * * * * cd /srv/cveye && /srv/cveye/venv/bin/python manage.py run_scheduled_scans >> /srv/cveye/logs/scans.log 2>&1
```

---

## Déploiement

Le script `install.sh` installe CVEye sur un serveur Debian/Ubuntu : paquets système, PostgreSQL, environnement Python, service Gunicorn, Nginx en reverse proxy, cron pour les scans programmés et, si on le souhaite, un certificat HTTPS avec Certbot. Il se lance avec un utilisateur non root qui a les droits sudo.

Sur notre VPS, on a aussi :

- fermé les ports inutiles avec le pare-feu
- masqué la version de Nginx
- activé Fail2ban
- forcé HTTPS (HSTS, cookies sécurisés)

---

## Limites connues

- la détection de services reconnaît surtout HTTP, SSH et FTP ; les autres services (MySQL, SMTP, RDP...) apparaissent souvent comme inconnus
- pas encore de cache pour les requêtes à l'API NVD
- les priorités KEV et EPSS ne sont pas encore prises en compte

---

## Équipe

| Membre | Ce qu'il/elle a fait |
|---|---|
| Abdelmalek Said Allahoum | Moteur de scan, intégration backend/frontend, alertes mail, détection des serveurs hors service, rapports PDF, déploiement et sécurisation du VPS |
| Samy Benmeziane | Recherche des CVE via l'API NVD, recherche manuelle sur plusieurs bases (NVD, CIRCL, OSV, Vulners), gestion des rôles admin/utilisateur, modèle de la base de données (avec Abdelmalek), étude des outils existants, participation au déploiement |
| Valeriia Oliinyk | Pages de connexion et d'inscription, dashboard |
| Hadrien Leclair | Page d'ajout des cibles, page des rapports |

Le cahier des charges, le cahier de conception et le cahier de recette ont été rédigés par toute l'équipe.

---

## Licence

Projet universitaire, usage pédagogique uniquement.
