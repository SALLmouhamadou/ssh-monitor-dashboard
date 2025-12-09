import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# Configuration de la page
st.set_page_config(
    page_title="SSH Monitor Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
            # Créer un graphique matplotlib
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.plot(hourly_data.index, hourly_data.values, 
                   marker='o', linewidth=2, markersize=6, color='#4444ff')
            ax.fill_between(hourly_data.index, hourly_data.values, alpha=0.3, color='#4444ff')
            ax.set_xlabel('Heure', fontsize=12)
            ax.set_ylabel('Nombre d\'événements', fontsize=12)
            ax.set_title('Distribution des événements par heure', fontsize=14, fontweight='bold')
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            
            st.pyplot(fig)
            
            # Statistiques temporelles
            with st.expander("📋 Statistiques horaires"):
                if len(hourly_data) > 0:
                    st.write(f"**Heure la plus active :** {hourly_data.idxmax().strftime('%H:%M')} ({hourly_data.max()} événements)")
                    st.write(f"**Heure la moins active :** {hourly_data.idxmin().strftime('%H:%M')} ({hourly_data.min()} événements)")
                    st.write(f"**Moyenne par heure :** {hourly_data.mean():.1f} événements")
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
            # Graphique en camembert
            fig, ax = plt.subplots(figsize=(10, 6))
            colors_pie = plt.cm.Set3(range(len(event_counts)))
            wedges, texts, autotexts = ax.pie(
                event_counts.values,
                labels=[f"{evt}\n{EVENT_DESCRIPTIONS.get(evt, 'Unknown')}" for evt in event_counts.index],
                autopct='%1.1f%%',
                startangle=90,
                colors=colors_pie
            )
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            ax.set_title('Répartition des types d\'événements', fontsize=14, fontweight='bold')
            plt.tight_layout()
            
            st.pyplot(fig)
        
        with col_table:
            st.markdown("##### 📊 Détails")
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