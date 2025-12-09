import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import re
import io
import os

# Configuration de la page
st.set_page_config(
    page_title="SSH Monitor Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# FONCTION DE PARSING DES LOGS SSH
# ============================================================================

def parse_ssh_log(log_content):
    """
    Parse un fichier de log SSH brut et retourne un DataFrame au format attendu.
    Format attendu: Timestamp, EventId, SourceIP, User, Raw_Message
    """
    
    # Patterns regex pour extraire les informations
    patterns = {
        'E27': r'POSSIBLE BREAK-IN ATTEMPT',
        'E13': r'Invalid user (\w+) from',
        'E12': r'input_userauth_request: invalid user',
        'E21': r'pam_unix\(sshd:auth\): check pass; user unknown',
        'E19': r'pam_unix\(sshd:auth\): authentication failure',
        'E20': r'pam_unix\(sshd:auth\): authentication failure.*root',
        'E10': r'Failed password for invalid user',
        'E9': r'Failed password for root',
        'E2': r'Connection closed by',
        'E5': r'Too many authentication failures',
        'E17': r'PAM \d+ more authentication failures',
        'E18': r'PAM service\(sshd\) ignoring max retries',
        'E24': r'Received disconnect from',
        'E14': r'message repeated'
    }
    
    # Pattern pour extraire l'IP
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    # Pattern pour extraire l'utilisateur
    user_patterns = [
        r'Invalid user (\w+) from',
        r'Failed password for invalid user (\w+) from',
        r'Failed password for (\w+) from',
        r'user[=: ]+(\w+)',
        r'Accepted password for (\w+) from'
    ]
    # Pattern pour le timestamp
    timestamp_pattern = r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    
    parsed_data = []
    
    lines = log_content.split('\n')
    
    for line in lines:
        if not line.strip() or 'sshd' not in line.lower():
            continue
        
        # Extraire le timestamp
        timestamp_match = re.search(timestamp_pattern, line)
        timestamp = timestamp_match.group(1) if timestamp_match else 'None'
        
        # Déterminer le type d'événement
        event_id = 'E0'  # Événement inconnu par défaut
        for evt_id, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                event_id = evt_id
                break
        
        # Extraire l'IP source
        ip_match = re.search(ip_pattern, line)
        source_ip = ip_match.group(1) if ip_match else 'None'
        
        # Extraire l'utilisateur
        user = 'None'
        for user_pat in user_patterns:
            user_match = re.search(user_pat, line, re.IGNORECASE)
            if user_match:
                user = user_match.group(1)
                break
        
        parsed_data.append({
            'Timestamp': timestamp,
            'EventId': event_id,
            'SourceIP': source_ip,
            'User': user,
            'Raw_Message': line.strip()
        })
    
    return pd.DataFrame(parsed_data)

# Fonction de chargement des données avec cache
@st.cache_data
def load_data():
    """
    Charge et prétraite les données SSH depuis le fichier CSV.
    Le décorateur @st.cache_data évite de recharger les données à chaque interaction.
    """
    try:
        # Charger le CSV
        df = pd.read_csv('datasetssh.csv')
        
        # Convertir la colonne Timestamp en datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%b %d %H:%M:%S')
        
        # Ajouter l'année (2024 par défaut pour les logs)
        df['Timestamp'] = df['Timestamp'].apply(lambda x: x.replace(year=2024))
        
        # Trier par timestamp
        df = df.sort_values('Timestamp')
        
        return df
    except FileNotFoundError:
        st.error("❌ Fichier 'dataset_ssh.csv' introuvable. Veuillez placer le fichier dans le dossier du projet.")
        return None
    except Exception as e:
        st.error(f"❌ Erreur lors du chargement des données : {e}")
        return None

# Fonction pour calculer les statistiques
def calculate_statistics(df):
    """Calcule les statistiques clés du dataset"""
    # Filtrer les valeurs None et NaN pour les IPs
    valid_ips = df['SourceIP'][(df['SourceIP'] != 'None') & (pd.notna(df['SourceIP']))]
    valid_users = df['User'][(df['User'] != 'None') & (pd.notna(df['User']))]
    
    stats = {
        'total_events': len(df),
        'unique_ips': valid_ips.nunique(),
        'unique_users': valid_users.nunique(),
        'failed_attempts': len(df[df['EventId'].isin(['E9', 'E10'])]),
        'breakin_attempts': len(df[df['EventId'] == 'E27'])
    }
    return stats

# Fonction pour obtenir le top des IPs
def get_top_ips(df, n=5):
    """Retourne les N IPs les plus actives"""
    # Filtrer les valeurs None et NaN
    valid_ips = df[(df['SourceIP'] != 'None') & (pd.notna(df['SourceIP']))]
    ip_counts = valid_ips['SourceIP'].value_counts().head(n)
    return ip_counts

# Fonction pour obtenir l'évolution temporelle
def get_temporal_evolution(df):
    """Retourne l'évolution des événements par heure"""
    df_temp = df.copy()
    df_temp['Hour'] = df_temp['Timestamp'].dt.floor('H')
    hourly_counts = df_temp.groupby('Hour').size()
    return hourly_counts

# Dictionnaire de description des événements
EVENT_DESCRIPTIONS = {
    'E2': 'Connection closed',
    'E5': 'Too many auth failures',
    'E9': 'Failed password (root)',
    'E10': 'Failed password (invalid user)',
    'E12': 'Invalid user auth request',
    'E13': 'Invalid user',
    'E14': 'Message repeated',
    'E17': 'PAM auth failures',
    'E18': 'PAM ignoring max retries',
    'E19': 'PAM auth failure',
    'E20': 'PAM auth failure (root)',
    'E21': 'PAM check pass - user unknown',
    'E24': 'Received disconnect',
    'E27': '⚠️ POSSIBLE BREAK-IN ATTEMPT'
}

# ============================================================================
# INTERFACE PRINCIPALE
# ============================================================================

# Titre principal
st.title("🛡️ SSH Security Monitor Dashboard")
st.markdown("---")

# ============================================================================
# SECTION UPLOAD DE FICHIER LOG
# ============================================================================

with st.expander("📤 Importer un nouveau fichier de logs SSH", expanded=False):
    st.markdown("""
    **Instructions :** Uploadez un fichier de logs SSH brut (.log ou .txt).
    Le fichier sera automatiquement parsé et les données seront sauvegardées dans `datasetssh.csv`.
    """)
    
    uploaded_file = st.file_uploader(
        "Choisir un fichier de logs SSH",
        type=['log', 'txt'],
        help="Formats acceptés: .log, .txt - Le fichier doit contenir des logs SSH au format syslog"
    )
    
    if uploaded_file is not None:
        # Lire le contenu du fichier
        log_content = uploaded_file.read().decode('utf-8', errors='ignore')
        
        # Afficher un aperçu
        st.markdown("**📋 Aperçu du fichier (5 premières lignes) :**")
        preview_lines = log_content.split('\n')[:5]
        for line in preview_lines:
            st.code(line, language="text")
        
        col_btn1, col_btn2 = st.columns(2)
        
        with col_btn1:
            if st.button("🔄 Parser et sauvegarder", type="primary", use_container_width=True):
                with st.spinner("Parsing du fichier en cours..."):
                    # Parser le fichier
                    df_parsed = parse_ssh_log(log_content)
                    
                    if len(df_parsed) > 0:
                        # Sauvegarder dans datasetssh.csv
                        df_parsed.to_csv('datasetssh.csv', index=False)
                        
                        # Vider le cache pour recharger les nouvelles données
                        st.cache_data.clear()
                        
                        st.success(f"✅ {len(df_parsed)} événements parsés et sauvegardés avec succès!")
                        st.info("🔄 Rechargement automatique des données...")
                        
                        # Afficher les statistiques du parsing
                        st.markdown("**📊 Résumé du parsing :**")
                        col_s1, col_s2, col_s3 = st.columns(3)
                        with col_s1:
                            st.metric("Total événements", len(df_parsed))
                        with col_s2:
                            st.metric("Types d'événements", df_parsed['EventId'].nunique())
                        with col_s3:
                            valid_ips = df_parsed[df_parsed['SourceIP'] != 'None']
                            st.metric("IPs uniques", valid_ips['SourceIP'].nunique())
                        
                        # Rerun pour afficher les nouvelles données
                        st.rerun()
                    else:
                        st.error("❌ Aucun événement SSH trouvé dans le fichier. Vérifiez que le format est correct.")
        
        with col_btn2:
            if st.button("❌ Annuler", use_container_width=True):
                st.rerun()

st.markdown("---")

# Chargement des données
df = load_data()

if df is not None:
    # ========================================================================
    # SIDEBAR - Filtres et informations
    # ========================================================================
    with st.sidebar:
        st.header("⚙️ Configuration & Filtres")
        
        st.markdown("### 🔍 Filtres Actifs")
        
        # ---- Filtre par Type d'Événement ----
        st.markdown("#### 📋 Type d'Événement")
        
        # Option "Tous les événements"
        event_all = st.checkbox("Tous les événements", value=True, key="event_all")
        
        if event_all:
            selected_events = df['EventId'].unique().tolist()
        else:
            # Créer des options avec descriptions
            event_options = sorted(df['EventId'].unique())
            event_labels = [f"{evt} - {EVENT_DESCRIPTIONS.get(evt, 'Unknown')}" for evt in event_options]
            
            selected_event_labels = st.multiselect(
                "Sélectionnez les types d'événements",
                options=event_labels,
                default=event_labels,
                help="Choisissez un ou plusieurs types d'événements à analyser"
            )
            
            # Extraire les EventId des labels sélectionnés
            selected_events = [label.split(' - ')[0] for label in selected_event_labels]
        
        st.markdown("---")
        
        # ---- Filtre par IP ----
        st.markdown("#### 🌐 Adresses IP")
        
        # Obtenir les IPs uniques (exclure 'None' et NaN)
        available_ips = sorted([ip for ip in df['SourceIP'].unique() if pd.notna(ip) and str(ip) != 'None'])
        
        # Option "Toutes les IPs"
        ip_all = st.checkbox("Toutes les IPs", value=True, key="ip_all")
        
        if ip_all:
            selected_ips = available_ips
        else:
            # Mode de sélection
            ip_mode = st.radio(
                "Mode de sélection",
                options=["Sélection multiple", "Top N IPs", "Recherche par pattern"],
                horizontal=False
            )
            
            if ip_mode == "Sélection multiple":
                selected_ips = st.multiselect(
                    "Sélectionnez les IPs",
                    options=available_ips,
                    default=available_ips[:5] if len(available_ips) > 5 else available_ips,
                    help="Choisissez une ou plusieurs IPs à analyser"
                )
            
            elif ip_mode == "Top N IPs":
                top_n = st.slider(
                    "Nombre d'IPs les plus actives",
                    min_value=1,
                    max_value=min(20, len(available_ips)),
                    value=5,
                    help="Sélectionne les N IPs générant le plus d'événements"
                )
                # Obtenir les top N IPs
                valid_ips_df = df[(df['SourceIP'] != 'None') & (pd.notna(df['SourceIP']))]
                top_ips_list = valid_ips_df['SourceIP'].value_counts().head(top_n).index.tolist()
                selected_ips = top_ips_list
                
            else:  # Recherche par pattern
                ip_pattern = st.text_input(
                    "Pattern de recherche",
                    value="",
                    placeholder="Ex: 173.234 ou .186",
                    help="Recherche les IPs contenant ce pattern"
                )
                if ip_pattern:
                    selected_ips = [ip for ip in available_ips if ip_pattern in ip]
                else:
                    selected_ips = available_ips
        
        st.markdown("---")
        
        # ---- Filtre par Utilisateur ----
        st.markdown("#### 👤 Utilisateurs")
        
        available_users = sorted([user for user in df['User'].unique() if pd.notna(user) and str(user) != 'None'])
        
        user_all = st.checkbox("Tous les utilisateurs", value=True, key="user_all")
        
        if user_all:
            selected_users = df['User'].unique().tolist()
        else:
            selected_users_list = st.multiselect(
                "Sélectionnez les utilisateurs",
                options=available_users,
                default=available_users[:5] if len(available_users) > 5 else available_users,
                help="Filtrer par nom d'utilisateur ciblé"
            )
            # Inclure 'None' dans la sélection
            selected_users = selected_users_list + ['None']
        
        st.markdown("---")
        
        # ---- Filtre Temporel ----
        st.markdown("#### 📅 Période Temporelle")
        
        min_date = df['Timestamp'].min()
        max_date = df['Timestamp'].max()
        
        time_range = st.slider(
            "Sélectionnez la plage horaire",
            min_value=min_date.to_pydatetime(),
            max_value=max_date.to_pydatetime(),
            value=(min_date.to_pydatetime(), max_date.to_pydatetime()),
            format="DD/MM HH:mm",
            help="Filtrer les événements par période"
        )
        
        st.markdown("---")
        
        # ---- Bouton Reset ----
        if st.button("🔄 Réinitialiser tous les filtres", use_container_width=True):
            st.rerun()
        
        st.markdown("---")
        st.markdown("### ℹ️ Informations Dataset")
        st.info(f"📅 Période complète : {df['Timestamp'].min().strftime('%d %b %Y %H:%M')} → {df['Timestamp'].max().strftime('%d %b %Y %H:%M')}")
        
        st.markdown("---")
        st.markdown("### 📖 À propos")
        st.markdown("""
        Ce dashboard analyse les logs SSH pour détecter :
        - 🔴 Tentatives d'intrusion
        - 🔐 Échecs d'authentification
        - 📊 Patterns d'attaque
        - 🌐 IPs suspectes
        """)
    
    # ========================================================================
    # APPLICATION DES FILTRES
    # ========================================================================
    
    # Appliquer tous les filtres
    df_filtered = df[
        (df['EventId'].isin(selected_events)) &
        (
            (df['SourceIP'].isin(selected_ips)) | 
            (df['SourceIP'] == 'None') | 
            (pd.isna(df['SourceIP']))
        ) &
        (df['User'].isin(selected_users)) &
        (df['Timestamp'] >= time_range[0]) &
        (df['Timestamp'] <= time_range[1])
    ]
    
    # ========================================================================
    # FEEDBACK UTILISATEUR
    # ========================================================================
    
    if len(df_filtered) == 0:
        st.warning("⚠️ Aucun événement ne correspond aux filtres sélectionnés. Veuillez ajuster vos critères de filtrage.")
        st.info("💡 **Conseil** : Essayez de désactiver certains filtres ou d'élargir votre sélection.")
        
        # Afficher un résumé des filtres actifs
        with st.expander("🔍 Filtres actuellement actifs"):
            st.write(f"**Événements sélectionnés :** {len(selected_events)}")
            st.write(f"**IPs sélectionnées :** {len(selected_ips)}")
            st.write(f"**Utilisateurs sélectionnés :** {len(selected_users)}")
            st.write(f"**Période :** {time_range[0].strftime('%d/%m %H:%M')} - {time_range[1].strftime('%d/%m %H:%M')}")
        
        st.stop()  # Arrêter l'exécution si aucune donnée
    
    # Afficher un bandeau d'information sur le filtrage
    if len(df_filtered) < len(df):
        col_info1, col_info2 = st.columns([3, 1])
        with col_info1:
            st.info(f"🔍 **Filtres actifs** : Affichage de {len(df_filtered):,} événements sur {len(df):,} ({len(df_filtered)/len(df)*100:.1f}%)")
        with col_info2:
            if st.button("❌ Effacer les filtres"):
                st.rerun()
    
    # ========================================================================
    # MÉTRIQUES PRINCIPALES
    # ========================================================================
    st.header("📊 Vue d'ensemble")
    
    stats = calculate_statistics(df_filtered)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # Calculer le delta par rapport au dataset complet
        delta_events = len(df_filtered) - len(df)
        st.metric(
            label="🔢 Total des Événements",
            value=f"{stats['total_events']:,}",
            delta=f"{delta_events:+,}" if len(df_filtered) < len(df) else None,
            help="Nombre total d'événements enregistrés (après filtrage)"
        )
    
    with col2:
        st.metric(
            label="🌐 IPs Uniques",
            value=stats['unique_ips'],
            help="Nombre d'adresses IP distinctes dans les données filtrées"
        )
    
    with col3:
        st.metric(
            label="❌ Échecs d'Authentification",
            value=stats['failed_attempts'],
            delta=f"{(stats['failed_attempts']/stats['total_events']*100):.1f}%" if stats['total_events'] > 0 else "0%",
            delta_color="inverse",
            help="Nombre de tentatives de connexion échouées (E9, E10)"
        )
    
    with col4:
        st.metric(
            label="⚠️ Tentatives d'Intrusion",
            value=stats['breakin_attempts'],
            delta="Critique" if stats['breakin_attempts'] > 0 else "Aucune",
            delta_color="off",
            help="Événements marqués comme POSSIBLE BREAK-IN ATTEMPT (E27)"
        )
    
    st.markdown("---")
    
    # ========================================================================
    # VISUALISATIONS
    # ========================================================================


    """" 
    Ce bloc de code configure une section d'analyse visuelle dans une application Streamlit. 
    Il commence par afficher un titre principal ("Analyses Détaillées") et divise l'écran en deux colonnes égales. 
    Le code se concentre ensuite sur la colonne de gauche pour analyser les "IPs Agressives". Il appelle d'abord 
    une fonction (get_top_ips) pour récupérer les 5 adresses IP les plus actives à partir d'un DataFrame filtré.

    Si des données sont trouvées, le script génère un graphique à barres horizontales via la bibliothèque Matplotlib 
    (avec une palette de couleurs rouges pour signifier l'urgence), l'affiche dans l'interface, et ajoute un menu déroulant (expander)
    contenant le tableau des données brutes. Si aucune donnée n'est trouvée (le else à la fin), des messages d'avertissement informatifs
    sont affichés pour guider l'utilisateur.
   """
    st.header("📈 Analyses Détaillées")
    
    # Créer deux colonnes pour les graphiques
    col_left, col_right = st.columns(2)
    
    # ---- COLONNE GAUCHE : Top IPs Agressives ----
    with col_left:
        st.subheader("🎯 Top 5 des IPs les plus Actives")
        
        top_ips = get_top_ips(df_filtered, n=5)
        
        if not top_ips.empty and len(top_ips) > 0:
            # Créer un graphique matplotlib
            fig, ax = plt.subplots(figsize=(10, 6))
            colors = ['#ff4444', '#ff6666', '#ff8888', '#ffaaaa', '#ffcccc']
            top_ips.plot(kind='barh', ax=ax, color=colors[:len(top_ips)])
            ax.set_xlabel('Nombre d\'événements', fontsize=12)
            ax.set_ylabel('Adresse IP', fontsize=12)
            ax.set_title('IPs générant le plus d\'événements', fontsize=14, fontweight='bold')
            ax.invert_yaxis()
            plt.tight_layout()
            
            st.pyplot(fig)
            
            # Afficher aussi les données sous forme de tableau
            with st.expander("📋 Voir les détails"):
                st.dataframe(
                    pd.DataFrame({
                        'IP': top_ips.index,
                        'Nombre d\'événements': top_ips.values
                    }).reset_index(drop=True),
                    use_container_width=True
                )
        else:
            st.warning("⚠️ Aucune donnée IP disponible pour les filtres sélectionnés.")
            st.info("💡 Essayez d'élargir votre sélection d'IPs ou de types d'événements.")
    
    # ---- COLONNE DROITE : Évolution Temporelle ----
    
    with col_right:
        st.subheader("⏰ Évolution Temporelle des Attaques")
        
        hourly_data = get_temporal_evolution(df_filtered)
        
        if not hourly_data.empty and len(hourly_data) > 0:
            # Créer un graphique matplotlib amélioré
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Formater les heures pour l'affichage
            hours_formatted = [h.strftime('%d/%m\n%H:%M') for h in hourly_data.index]
            x_positions = range(len(hourly_data))
            
            # Graphique en barres pour plus de clarté
            bars = ax.bar(x_positions, hourly_data.values, 
                         color='#4a90d9', edgecolor='#2c5282', alpha=0.8)
            
            # Ligne de tendance
            ax.plot(x_positions, hourly_data.values, 
                   color='#e53e3e', linewidth=2, marker='o', markersize=4, label='Tendance')
            
            # Ligne de moyenne
            moyenne = hourly_data.mean()
            ax.axhline(y=moyenne, color='#48bb78', linestyle='--', linewidth=2, 
                      label=f'Moyenne: {moyenne:.0f} évts/h')
            
            # Marquer le pic d'activité
            max_idx = hourly_data.values.argmax()
            ax.annotate(f'⚠️ Pic: {hourly_data.max()}', 
                       xy=(max_idx, hourly_data.max()),
                       xytext=(max_idx, hourly_data.max() + hourly_data.max()*0.1),
                       fontsize=10, fontweight='bold', color='#e53e3e',
                       ha='center')
            
            # Configurer les axes
            ax.set_xticks(x_positions)
            ax.set_xticklabels(hours_formatted, fontsize=8)
            ax.set_xlabel('Date et Heure', fontsize=12)
            ax.set_ylabel('Nombre d\'événements', fontsize=12)
            ax.set_title('📊 Activité par Tranche Horaire', fontsize=14, fontweight='bold')
            ax.grid(True, alpha=0.3, axis='y')
            ax.legend(loc='upper right', fontsize=9)
            
            # Réduire le nombre de labels si trop nombreux
            if len(x_positions) > 10:
                step = len(x_positions) // 10
                ax.set_xticks([x for i, x in enumerate(x_positions) if i % step == 0])
                ax.set_xticklabels([h for i, h in enumerate(hours_formatted) if i % step == 0], fontsize=8)
            
            plt.tight_layout()
            
            st.pyplot(fig)
            
            # Statistiques temporelles améliorées
            with st.expander("📋 Statistiques horaires"):
                if len(hourly_data) > 0:
                    col_stat1, col_stat2 = st.columns(2)
                    with col_stat1:
                        st.metric("🔴 Pic d'activité", 
                                 f"{hourly_data.idxmax().strftime('%d/%m %H:%M')}", 
                                 f"{hourly_data.max()} événements")
                        st.metric("📊 Moyenne/heure", f"{hourly_data.mean():.1f}")
                    with col_stat2:
                        st.metric("🟢 Période calme", 
                                 f"{hourly_data.idxmin().strftime('%d/%m %H:%M')}", 
                                 f"{hourly_data.min()} événements")
                        st.metric("📈 Total périodes", f"{len(hourly_data)}")
        else:
            st.warning("⚠️ Aucune donnée temporelle disponible pour les filtres sélectionnés.")
            st.info("💡 Essayez d'élargir votre plage horaire.")
    
    # ========================================================================
    # ANALYSE PAR TYPE D'ÉVÉNEMENT
    # ========================================================================
    st.markdown("---")
    st.header("🔍 Répartition des Types d'Événements")
    
    event_counts = df_filtered['EventId'].value_counts()
    
    if not event_counts.empty:
        col_chart, col_table = st.columns([2, 1])
        
        with col_chart:
            # Graphique en barres horizontales
            fig, ax = plt.subplots(figsize=(10, 6))
            colors_bar = plt.cm.Set3(range(len(event_counts)))
            
            # Créer les labels avec description
            labels = [f"{evt} - {EVENT_DESCRIPTIONS.get(evt, 'Unknown')}" for evt in event_counts.index]
            
            # Graphique en barres horizontales
            bars = ax.barh(labels, event_counts.values, color=colors_bar)
            
            # Ajouter les pourcentages à la fin de chaque barre
            total = event_counts.sum()
            for bar, value in zip(bars, event_counts.values):
                percentage = (value / total) * 100
                ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2, 
                       f'{percentage:.1f}%', va='center', fontsize=9)
            
            ax.set_xlabel('Nombre d\'événements', fontsize=12)
            ax.set_ylabel('Type d\'événement', fontsize=12)
            ax.set_title('Répartition des types d\'événements', fontsize=14, fontweight='bold')
            ax.invert_yaxis()  # Pour avoir le plus grand en haut
            plt.tight_layout()
            
            st.pyplot(fig)
        
        with col_table:
            st.markdown("##### 📊 Détails")
            
            # Graphique circulaire
            fig_pie, ax_pie = plt.subplots(figsize=(6, 6))
            colors_pie = plt.cm.Set3(range(len(event_counts)))
            wedges, texts, autotexts = ax_pie.pie(
                event_counts.values,
                labels=event_counts.index,
                autopct='%1.1f%%',
                startangle=90,
                colors=colors_pie
            )
            for autotext in autotexts:
                autotext.set_fontsize(8)
                autotext.set_fontweight('bold')
            ax_pie.set_title('Distribution', fontsize=12, fontweight='bold')
            plt.tight_layout()
            st.pyplot(fig_pie)
            
            # Tableau des données
            with st.expander("📋 Voir le tableau"):
                event_df = pd.DataFrame({
                    'Type': event_counts.index,
                    'Description': [EVENT_DESCRIPTIONS.get(evt, 'Unknown') for evt in event_counts.index],
                    'Nombre': event_counts.values,
                    'Pourcentage': [f"{(v/event_counts.sum()*100):.1f}%" for v in event_counts.values]
                })
                st.dataframe(event_df, use_container_width=True, hide_index=True)
    else:
        st.warning("⚠️ Aucune donnée d'événement disponible.")
    
    # ========================================================================
    # DONNÉES BRUTES
    # ========================================================================
    st.markdown("---")
    st.header("📄 Données Brutes")
    
    with st.expander("🔍 Voir les logs SSH filtrés", expanded=False):
        # Options d'affichage
        col_opt1, col_opt2 = st.columns(2)
        with col_opt1:
            show_columns = st.multiselect(
                "Colonnes à afficher",
                options=df_filtered.columns.tolist(),
                default=df_filtered.columns.tolist(),
                help="Sélectionnez les colonnes à afficher"
            )
        with col_opt2:
            sort_column = st.selectbox(
                "Trier par",
                options=df_filtered.columns.tolist(),
                index=0,
                help="Colonne utilisée pour le tri"
            )
            sort_order = st.radio("Ordre", ["Croissant", "Décroissant"], horizontal=True)
        
        # Appliquer les options
        df_display = df_filtered[show_columns].sort_values(
            by=sort_column,
            ascending=(sort_order == "Croissant")
        )
        
        st.dataframe(
            df_display,
            use_container_width=True,
            height=400
        )
        
        st.caption(f"Affichage de {len(df_filtered)} événements sur {len(df)} au total")
        
        # Bouton de téléchargement
        csv = df_filtered.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Télécharger les données filtrées (CSV)",
            data=csv,
            file_name=f"ssh_logs_filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

else:
    st.warning("⚠️ Impossible de charger les données. Veuillez vérifier que le fichier 'dataset_ssh.csv' est présent.")

# Footer
st.markdown("---")
st.caption("🛡️ SSH Security Monitor Dashboard | Développé avec Streamlit")