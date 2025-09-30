# respond.py
# Système de réponse
import json
import boto3
import logging

logger = logging.getLogger(__name__)

def block_iam_user(username):
    """
    Bloque un utilisateur IAM en supprimant ses clés d'accès et en attachant une politique DenyAll.
    """
    iam = boto3.client('iam')
    logger.warning(f"ACTION DE RÉPONSE: Tentative de blocage de l'utilisateur IAM '{username}'")

    try:
        # 1. Supprimer toutes les clés d'accès
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            logger.info(f"Suppression de la clé d'accès {key['AccessKeyId']} pour l'utilisateur {username}")
            iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])

        # 2. Attacher une politique DenyAll
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        }
        policy_name = "QuarantinePolicy"
        logger.info(f"Attachement de la politique '{policy_name}' à l'utilisateur {username}")
        iam.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(deny_policy)
        )
        
        logger.warning(f"SUCCÈS: L'utilisateur IAM '{username}' a été bloqué.")
        return True
    except Exception as e:
        logger.error(f"ERREUR lors du blocage de l'utilisateur IAM '{username}': {e}")
        return False

def isolate_ec2_instance(instance_id, region):
    """
    Isole une instance EC2 en la plaçant dans un groupe de sécurité de quarantaine.
    """
    ec2 = boto3.client('ec2', region_name=region)
    quarantine_sg_name = "QuarantineSG"
    logger.warning(f"ACTION DE RÉPONSE: Tentative d'isolation de l'instance EC2 '{instance_id}' dans la région {region}")

    try:
        # 1. Chercher ou créer le groupe de sécurité de quarantaine
        try:
            sg_response = ec2.describe_security_groups(GroupNames=[quarantine_sg_name])
            quarantine_sg_id = sg_response['SecurityGroups'][0]['GroupId']
            logger.info(f"Le groupe de sécurité de quarantaine '{quarantine_sg_name}' existe déjà ({quarantine_sg_id}).")
        except ec2.exceptions.ClientError as e:
            if 'InvalidGroup.NotFound' in str(e):
                logger.info(f"Création du groupe de sécurité de quarantaine '{quarantine_sg_name}'...")
                vpc_id = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['VpcId']
                new_sg = ec2.create_security_group(
                    GroupName=quarantine_sg_name,
                    Description="Quarantine - No inbound/outbound traffic allowed",
                    VpcId=vpc_id
                )
                quarantine_sg_id = new_sg['GroupId']
            else:
                raise e
        
        # 2. Remplacer les SG de l'instance par le SG de quarantaine
        logger.info(f"Application du SG de quarantaine '{quarantine_sg_id}' à l'instance '{instance_id}'")
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_sg_id]
        )
        
        logger.warning(f"SUCCÈS: L'instance EC2 '{instance_id}' a été isolée.")
        return True
    except Exception as e:
        logger.error(f"ERREUR lors de l'isolation de l'instance EC2 '{instance_id}': {e}")
        return False
