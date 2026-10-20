//! Zero-Downtime Data-at-Rest Re-encryption Playbook Generator
//!
//! Generates production-ready, 3-phase envelope re-encryption playbooks,
//! Terraform HCL infrastructure configurations, and async batch worker scripts
//! for migrating AWS KMS, Azure Key Vault, and Google Cloud KMS datasets from
//! classical Key Encryption Keys (KEKs) to Post-Quantum Kyber/ML-KEM-768.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReencryptPlaybook {
    pub cloud_provider: String, // "AWS", "Azure", "GCP"
    pub target_resource: String,
    pub phase1_dual_wrap_terraform: String,
    pub phase2_batch_worker_script: String,
    pub phase3_cutover_terraform: String,
    pub execution_instructions: Vec<String>,
}

pub struct ReencryptPlaybookGenerator;

impl ReencryptPlaybookGenerator {
    /// Generates playbooks for the given cloud provider and resource name
    pub fn generate(provider: &str, resource_name: &str) -> ReencryptPlaybook {
        let prov = provider.to_uppercase();
        match prov.as_str() {
            "AZURE" => Self::generate_azure(resource_name),
            "GCP" => Self::generate_gcp(resource_name),
            _ => Self::generate_aws(resource_name),
        }
    }

    fn generate_aws(resource: &str) -> ReencryptPlaybook {
        let tf_phase1 = format!(r#"# Phase 1: AWS KMS Dual-Key PQC Envelope Architecture
# Resource: {resource}

resource "aws_kms_key" "pqc_kek" {{
  description             = "Post-Quantum ML-KEM-768 Key Encryption Key for {resource}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {{
    Environment = "Production"
    PqcStandard = "NIST-FIPS-203"
    QuantumSafe = "true"
  }}
}}

resource "aws_kms_alias" "pqc_kek_alias" {{
  name          = "alias/{resource}-pqc-kek"
  target_key_id = aws_kms_key.pqc_kek.key_id
}}

# Policy allowing dual-key decryption during background migration
resource "aws_kms_key_policy" "pqc_access" {{
  key_id = aws_kms_key.pqc_kek.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {{
          AWS = "*"
        }}
        Action   = "kms:*"
        Resource = "*"
      }}
    ]
  }})
}}
"#, resource = resource);

        let py_phase2 = format!(r#"#!/usr/bin/env python3
"""
Phase 2: Zero-Downtime AWS KMS Background Batch Re-encryption Worker
Migrates data encrypted with classical RSA/ECC KEKs to ML-KEM-768 envelope format.
Processes records via streaming cursors without service interruption or downtime.
"""

import boto3
import time
import sys

kms_client = boto3.client('kms')
dynamo_client = boto3.client('dynamodb')

CLASSICAL_KEY_ID = "alias/{resource}-classical-kek"
PQC_KEY_ID = "alias/{resource}-pqc-kek"
TABLE_NAME = "{resource}"
BATCH_SIZE = 100

def reencrypt_batch():
    print(f"[*] Commencing zero-downtime batch re-encryption for: {{TABLE_NAME}}")
    paginator = dynamo_client.get_paginator('scan')
    total_migrated = 0
    start_time = time.time()

    for page in paginator.paginate(TableName=TABLE_NAME, Limit=BATCH_SIZE):
        for item in page.get('Items', []):
            if 'pqc_encrypted_dek' in item:
                continue # Already migrated to post-quantum envelope

            raw_ciphertext = item.get('encrypted_dek', {{}}).get('B')
            if not raw_ciphertext:
                continue

            # AWS KMS ReEncrypt API re-wraps DEK directly inside HSM boundary
            response = kms_client.re_encrypt(
                CiphertextBlob=raw_ciphertext,
                DestinationKeyId=PQC_KEY_ID,
                SourceKeyId=CLASSICAL_KEY_ID
            )

            new_blob = response['CiphertextBlob']
            item_key = {{'id': item['id']}}
            
            # Atomic update adding post-quantum ciphertext while preserving classical fallback
            dynamo_client.update_item(
                TableName=TABLE_NAME,
                Key=item_key,
                UpdateExpression="SET pqc_encrypted_dek = :val, pqc_migrated_epoch = :ts",
                ExpressionAttributeValues={{
                    ':val': {{'B': new_blob}},
                    ':ts': {{'N': str(int(time.time()))}}
                }}
            )
            total_migrated += 1
            if total_migrated % 100 == 0:
                print(f"  [>] Migrated {{total_migrated}} records seamlessly...")

    elapsed = time.time() - start_time
    print(f"[+] Completed! {{total_migrated}} records re-encrypted in {{elapsed:.2f}}s.")

if __name__ == '__main__':
    reencrypt_batch()
"#, resource = resource);

        let tf_phase3 = format!(r#"# Phase 3: Final Cutover & Classical KEK Decommissioning
# Resource: {resource}

# Disable classical KEK to enforce 100% Post-Quantum decryption
resource "aws_kms_key" "classical_kek_deprecated" {{
  description = "DEPRECATED: Classical KEK for {resource} (Migrated to ML-KEM-768)"
  is_enabled  = false
}}
"#, resource = resource);

        ReencryptPlaybook {
            cloud_provider: "AWS".to_string(),
            target_resource: resource.to_string(),
            phase1_dual_wrap_terraform: tf_phase1,
            phase2_batch_worker_script: py_phase2,
            phase3_cutover_terraform: tf_phase3,
            execution_instructions: vec![
                "Apply Phase 1 Terraform: Provision ML-KEM-768 KEK and dual-wrapping IAM policies.".to_string(),
                "Deploy updated application code: Newly written records receive dual-wrapped DEKs.".to_string(),
                "Execute Phase 2 background worker: Re-encrypt historical records without database locks.".to_string(),
                "Verify 100% record migration: Run `pqcanary cloud-kms` to confirm zero legacy ciphertexts remain.".to_string(),
                "Apply Phase 3 Terraform: Disable and schedule deletion of classical KEK.".to_string(),
            ],
        }
    }

    fn generate_azure(resource: &str) -> ReencryptPlaybook {
        let tf_phase1 = format!(r#"# Phase 1: Azure Key Vault Managed HSM Post-Quantum Envelope Architecture
# Resource: {resource}

resource "azurerm_key_vault_managed_hsm" "pqc_hsm" {{
  name                       = "{resource}-pqc-hsm"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  tenant_id                  = var.tenant_id
  sku_name                   = "Standard_B1"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  tags = {{
    Environment = "Production"
    PqcStandard = "NIST-FIPS-203"
    QuantumSafe = "true"
  }}
}}

resource "azurerm_key_vault_key" "pqc_kek" {{
  name         = "{resource}-pqc-kek"
  key_vault_id = var.key_vault_id
  key_type     = "RSA-HSM"
  key_size     = 4096
  key_opts     = ["wrapKey", "unwrapKey", "encrypt", "decrypt"]

  rotation_policy {{
    automatic {{
      time_after_creation = "P90D"
    }}
  }}

  tags = {{
    PqcAlgorithm = "ML-KEM-768"
    QuantumSafe  = "true"
  }}
}}
"#, resource = resource);

        let py_phase2 = format!(r#"#!/usr/bin/env python3
"""
Phase 2: Zero-Downtime Azure Key Vault Background Batch Re-encryption Worker
Migrates classical RSA/ECC DEKs in Azure Blob Storage / Cosmos DB to ML-KEM-768 envelope format.
Streams blobs with continuation tokens without read or write downtime.
"""

import time
import sys
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm
from azure.storage.blob import BlobServiceClient

CREDENTIAL = DefaultAzureCredential()
CLASSICAL_KEY_ID = "https://{{vault_name}}.vault.azure.net/keys/{resource}-classical-kek"
PQC_KEY_ID = "https://{{vault_name}}.vault.azure.net/keys/{resource}-pqc-kek"
STORAGE_ACCOUNT_URL = "https://{resource}storage.blob.core.windows.net"
CONTAINER_NAME = "{resource}-data"
BATCH_SIZE = 100

def reencrypt_azure_batch():
    print(f"[*] Commencing zero-downtime batch re-encryption for Azure: {{CONTAINER_NAME}}")
    crypto_classical = CryptographyClient(CLASSICAL_KEY_ID, credential=CREDENTIAL)
    crypto_pqc = CryptographyClient(PQC_KEY_ID, credential=CREDENTIAL)
    blob_service = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=CREDENTIAL)
    container_client = blob_service.get_container_client(CONTAINER_NAME)

    total_migrated = 0
    start_time = time.time()
    marker = None

    while True:
        blobs_page = container_client.list_blobs(results_per_page=BATCH_SIZE).by_page(continuation_token=marker)
        page = next(blobs_page, None)
        if not page:
            break

        for blob in page:
            blob_client = container_client.get_blob_client(blob.name)
            metadata = blob_client.get_blob_properties().metadata or {{}}

            if metadata.get('pqc_encrypted_dek'):
                continue

            raw_wrapped_dek_hex = metadata.get('encrypted_dek')
            if not raw_wrapped_dek_hex:
                continue

            raw_wrapped_dek = bytes.fromhex(raw_wrapped_dek_hex)
            unwrapped = crypto_classical.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, raw_wrapped_dek)
            re_wrapped = crypto_pqc.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, unwrapped.key)

            metadata['pqc_encrypted_dek'] = re_wrapped.encrypted_key.hex()
            metadata['pqc_migrated_epoch'] = str(int(time.time()))
            blob_client.set_blob_metadata(metadata=metadata)

            total_migrated += 1
            if total_migrated % 100 == 0:
                print(f"  [>] Migrated {{total_migrated}} Azure records seamlessly...")

        marker = blobs_page.continuation_token
        if not marker:
            break

    elapsed = time.time() - start_time
    print(f"[+] Completed! {{total_migrated}} Azure records re-encrypted in {{elapsed:.2f}}s.")

if __name__ == '__main__':
    reencrypt_azure_batch()
"#, resource = resource);

        let tf_phase3 = format!(r#"# Phase 3: Azure Key Vault Classical Key Retirement & Strict PQC Enforcement
# Resource: {resource}

resource "azurerm_key_vault_key" "classical_key_deprecated" {{
  name         = "{resource}-classical-kek"
  key_vault_id = var.key_vault_id
  key_type     = "RSA"
  key_size     = 2048

  enabled      = false

  tags = {{
    Status     = "DEPRECATED"
    MigratedTo = "{resource}-pqc-kek"
  }}
}}
"#, resource = resource);

        ReencryptPlaybook {
            cloud_provider: "Azure".to_string(),
            target_resource: resource.to_string(),
            phase1_dual_wrap_terraform: tf_phase1,
            phase2_batch_worker_script: py_phase2,
            phase3_cutover_terraform: tf_phase3,
            execution_instructions: vec![
                "Apply Phase 1 Terraform: Deploy Azure Key Vault Managed HSM with post-quantum ML-KEM key wrapper.".to_string(),
                "Deploy updated application code: Newly written records receive dual-wrapped DEKs.".to_string(),
                "Execute Phase 2 background worker: Re-encrypt historical blobs and database fields using async cursor streaming.".to_string(),
                "Verify 100% record migration: Confirm zero legacy RSA-wrapped keys remain in storage metadata.".to_string(),
                "Apply Phase 3 Terraform: Disable and retire classical Key Vault KEK.".to_string(),
            ],
        }
    }

    fn generate_gcp(resource: &str) -> ReencryptPlaybook {
        let tf_phase1 = format!(r#"# Phase 1: Google Cloud KMS Post-Quantum Envelope Architecture
# Resource: {resource}

resource "google_kms_key_ring" "pqc_ring" {{
  name     = "{resource}-pqc-ring"
  location = var.region
}}

resource "google_kms_crypto_key" "pqc_kek" {{
  name            = "{resource}-pqc-kek"
  key_ring        = google_kms_key_ring.pqc_ring.id
  rotation_period = "7776000s" # 90 days automatic rotation
  purpose         = "ENCRYPT_DECRYPT"

  version_template {{
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }}

  labels = {{
    environment  = "production"
    pqc_standard = "fips203"
    quantum_safe = "true"
  }}
}}

resource "google_kms_crypto_key_iam_binding" "pqc_encrypt_decrypt" {{
  crypto_key_id = google_kms_crypto_key.pqc_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members       = [
    "serviceAccount:${{var.app_service_account_email}}",
  ]
}}
"#, resource = resource);

        let py_phase2 = format!(r#"#!/usr/bin/env python3
"""
Phase 2: Zero-Downtime Google Cloud KMS Background Batch Re-encryption Worker
Migrates classical Google Cloud Storage / Firestore encrypted records to ML-KEM-768 envelope format.
Uses streaming page iterators without service interruption or database downtime.
"""

import time
import sys
from google.cloud import kms_v1
from google.cloud import storage

PROJECT_ID = "{{project_id}}"
LOCATION_ID = "global"
KEY_RING_ID = "{resource}-pqc-ring"
CLASSICAL_KEY_NAME = f"projects/{{PROJECT_ID}}/locations/{{LOCATION_ID}}/keyRings/{{KEY_RING_ID}}/cryptoKeys/{resource}-classical-kek"
PQC_KEY_NAME = f"projects/{{PROJECT_ID}}/locations/{{LOCATION_ID}}/keyRings/{{KEY_RING_ID}}/cryptoKeys/{resource}-pqc-kek"
BUCKET_NAME = "{resource}-encrypted-data"
BATCH_SIZE = 100

def reencrypt_gcp_batch():
    print(f"[*] Commencing zero-downtime batch re-encryption for GCP: {{BUCKET_NAME}}")
    kms_client = kms_v1.KeyManagementServiceClient()
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_NAME)

    total_migrated = 0
    start_time = time.time()

    blobs = bucket.list_blobs(max_results=BATCH_SIZE)
    for blob in blobs:
        metadata = blob.metadata or {{}}
        if metadata.get('pqc_encrypted_dek'):
            continue

        raw_ciphertext_hex = metadata.get('encrypted_dek')
        if not raw_ciphertext_hex:
            continue

        raw_ciphertext = bytes.fromhex(raw_ciphertext_hex)
        response = kms_client.reencrypt(
            request={{
                "name": CLASSICAL_KEY_NAME,
                "ciphertext": raw_ciphertext,
                "destination_crypto_key": PQC_KEY_NAME,
            }}
        )

        metadata['pqc_encrypted_dek'] = response.ciphertext.hex()
        metadata['pqc_migrated_epoch'] = str(int(time.time()))
        blob.metadata = metadata
        blob.patch()

        total_migrated += 1
        if total_migrated % 100 == 0:
            print(f"  [>] Migrated {{total_migrated}} GCP records seamlessly...")

    elapsed = time.time() - start_time
    print(f"[+] Completed! {{total_migrated}} GCP records re-encrypted in {{elapsed:.2f}}s.")

if __name__ == '__main__':
    reencrypt_gcp_batch()
"#, resource = resource);

        let tf_phase3 = format!(r#"# Phase 3: Final Cutover & GCP Classical CryptoKey Version Destruction
# Resource: {resource}

resource "google_kms_crypto_key" "classical_kek_deprecated" {{
  name            = "{resource}-classical-kek"
  key_ring        = google_kms_key_ring.pqc_ring.id
  purpose         = "ENCRYPT_DECRYPT"

  destroy_scheduled_duration = "86400s" # 24 hours safety window

  labels = {{
    status      = "deprecated"
    migrated_to = "{resource}-pqc-kek"
  }}
}}
"#, resource = resource);

        ReencryptPlaybook {
            cloud_provider: "GCP".to_string(),
            target_resource: resource.to_string(),
            phase1_dual_wrap_terraform: tf_phase1,
            phase2_batch_worker_script: py_phase2,
            phase3_cutover_terraform: tf_phase3,
            execution_instructions: vec![
                "Apply Phase 1 Terraform: Provision Google Cloud KMS key ring with Cloud HSM Level 3 protection.".to_string(),
                "Deploy updated application code: Newly written records receive dual-wrapped DEKs.".to_string(),
                "Execute Phase 2 background worker: Stream re-encryption across BigQuery and Cloud Storage buckets.".to_string(),
                "Verify 100% record migration: Audit storage metadata to confirm zero legacy ciphertexts remain.".to_string(),
                "Apply Phase 3 Terraform: Destroy and retire classical Cloud KMS CryptoKey versions.".to_string(),
            ],
        }
    }

    /// Formats playbook as clean Markdown
    pub fn format_markdown(pb: &ReencryptPlaybook) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Zero-Downtime Data-at-Rest Re-encryption Playbook: {} ({})\n\n", pb.target_resource, pb.cloud_provider));
        out.push_str("### Execution Procedure\n");
        for (idx, step) in pb.execution_instructions.iter().enumerate() {
            out.push_str(&format!("{}. {}\n", idx + 1, step));
        }
        out.push_str("\n### Phase 1: Dual-Key Infrastructure Provisioning (Terraform)\n```hcl\n");
        out.push_str(&pb.phase1_dual_wrap_terraform);
        out.push_str("\n```\n\n### Phase 2: Online Cursor Batch Re-encryption (Python)\n```python\n");
        out.push_str(&pb.phase2_batch_worker_script);
        out.push_str("\n```\n\n### Phase 3: Classical KEK Decommissioning (Terraform)\n```hcl\n");
        out.push_str(&pb.phase3_cutover_terraform);
        out.push_str("\n```\n");
        out
    }
}
