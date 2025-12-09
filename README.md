# 🛡️ SSH Security Monitor Dashboard

Un dashboard interactif d'analyse des logs SSH pour détecter et visualiser les tentatives d'intrusion et les patterns d'attaque.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.29.0-FF4B4B.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🌟 Fonctionnalités

### 📊 Vue d'ensemble
- **Métriques en temps réel** : Total événements, IPs uniques, échecs d'authentification, tentatives d'intrusion
- **Visualisations dynamiques** : Graphiques interactifs mis à jour en temps réel selon les filtres

### 🎛️ Filtres Interactifs
- **Par type d'événement** : Sélection multiple avec descriptions détaillées
- **Par adresse IP** : 
  - Sélection multiple manuelle
  - Top N IPs les plus actives
  - Recherche par pattern
- **Par utilisateur** : Filtrage des comptes ciblés
- **Par période temporelle** : Slider pour sélectionner une plage horaire

### 📈 Analyses Avancées
- Top 5 des IPs les plus agressives
- Évolution temporelle des attaques
- Répartition des types d'événements
- Export des données filtrées en CSV

## 🚀 Installation

### Prérequis
- Python 3.8 ou supérieur
- pip

### Installation locale

```bash
# Cloner le repository
git clone https://github.com/VOTRE-USERNAME/ssh-monitor-dashboard.git
cd ssh-monitor-dashboard

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
# Sur Windows :
venv\Scripts\activate
# Sur macOS/Linux :
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'application
streamlit run app.py
```

L'application sera accessible à l'adresse : `http://localhost:8501`

## 📁 Structure du Projet

```
ssh_monitor/
│
├── app.py                 # Application Streamlit principale
├── dataset_ssh.csv        # Données des logs SSH
├── requirements.txt       # Dépendances Python
├── .gitignore            # Fichiers ignorés par Git
└── README.md             # Documentation
```

## 📊 Format des Données

Le fichier `dataset_ssh.csv` doit contenir les colonnes suivantes :

| Colonne | Description | Exemple |
|---------|-------------|---------|
| Timestamp | Date et heure de l'événement | Dec 10 06:55:46 |
| EventId | Identifiant du type d'événement | E27 |
| SourceIP | Adresse IP source | 173.234.31.186 |
| User | Nom d'utilisateur ciblé | webmaster |
| Raw_Message | Message brut du log | reverse mapping checking... |

### Types d'Événements

- **E2** : Connection closed
- **E9** : Failed password (root)
- **E10** : Failed password (invalid user)
- **E27** : ⚠️ POSSIBLE BREAK-IN ATTEMPT
- Et plus...

## 🎨 Captures d'Écran

### Dashboard Principal
![Dashboard](https://via.placeholder.com/800x400?text=Dashboard+Principal)

### Filtres Interactifs
![Filtres](https://via.placeholder.com/800x400?text=Filtres+Interactifs)

## 🛠️ Technologies Utilisées

- **[Streamlit](https://streamlit.io/)** : Framework web pour applications de data science
- **[Pandas](https://pandas.pydata.org/)** : Manipulation et analyse de données
- **[Matplotlib](https://matplotlib.org/)** : Visualisations graphiques

## 📝 Utilisation

1. **Chargement automatique** : Les données sont chargées automatiquement au démarrage
2. **Navigation** : Utilisez la sidebar pour accéder aux filtres
3. **Filtrage** : Sélectionnez les critères dans les différentes sections
4. **Analyse** : Les graphiques se mettent à jour automatiquement
5. **Export** : Téléchargez les données filtrées via le bouton dédié

## 🔒 Sécurité

Ce dashboard est conçu pour l'analyse de logs SSH à des fins de :
- Détection d'intrusion
- Analyse de patterns d'attaque
- Identification d'IPs suspectes
- Audit de sécurité

⚠️ **Important** : Ne partagez jamais publiquement des logs contenant des informations sensibles ou des adresses IP réelles sans anonymisation préalable.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :

1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📜 License

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 👨‍💻 Auteur

**Votre Nom**
- GitHub: [@votre-username](https://github.com/votre-username)
- LinkedIn: [Votre Profil](https://linkedin.com/in/votre-profil)

## 🙏 Remerciements

- [Streamlit](https://streamlit.io/) pour le framework
- La communauté open source pour les bibliothèques utilisées
- Tous les contributeurs du projet

---

⭐ **Si ce projet vous a été utile, n'hésitez pas à lui donner une étoile !**