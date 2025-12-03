"# aws-forensic-realtime" 
 AWS Forensic Tool - Détection d'Incidents Temps Réel

  Vue d'Ensemble
Outil automatisé de détection et de réponse aux incidents de sécurité sur AWS.
Développé pour la société GROUPRIF dans le cadre d'un projet de stage.

  Fonctionnalités Principales
- ✅ **Détection temps réel** : < 3 minutes
- ✅ **3 scénarios critiques** : IAM, S3 public, Cryptojacking
(🔍 **Compromission IAM** - Détection de privilèges admin suspects
🗄️ **Buckets S3 publics** - Surveillance des modifications ACL
⛏️ **Cryptojacking** - Analyse du comportement des instances EC2)
- ✅ **Actions automatisées** : Blocage IP, isolation EC2
- ✅ **Alertes multi-canaux** : Slack, Email, SNS
- ✅ **Dashboard monitoring** : CloudWatch en temps réel
  
Architecture

![arch](https://github.com/user-attachments/assets/91eeeb88-c537-419b-a39a-b1afbfcad2f2)

Les résultats:

![1762710961950](https://github.com/user-attachments/assets/de301a6c-0680-44d3-b223-b5e2eda3e49d)
![1762710962195](https://github.com/user-attachments/assets/5367ff08-2e19-4e22-a394-dc809a6d292b)
