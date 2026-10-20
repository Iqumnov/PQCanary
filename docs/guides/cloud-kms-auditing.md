# Cloud KMS and Infrastructure Auditing Guide

This guide explains how to audit cloud Key Management Services (AWS KMS, Azure Key Vault, Google Cloud KMS) and Terraform Infrastructure-as-Code (IaC) scripts for quantum vulnerabilities and CNSA 2.0 compliance using PQCanary.

---

## 1. Cloud Key Vulnerabilities Overview

Cloud Key Management Services underpin corporate database encryption (TDE), envelope encryption, envelope decryption, and digital signing. When cloud KMS configurations utilize classical asymmetric keys (RSA or elliptic curves), they expose long-term assets to future decryption once a Cryptographically Relevant Quantum Computer arrives.

| Provider | Vulnerable Key Specifications | Safe / Recommended Alternative |
| :--- | :--- | :--- |
| **AWS KMS** | `RSA_2048`, `RSA_3072`, `RSA_4096`, `ECC_NIST_P256`, `ECC_NIST_P384`, `ECC_SECG_P256K1` | `SYMMETRIC_DEFAULT` (AES-256-GCM) or AWS KMS hybrid KEM |
| **Azure Key Vault** | `RSA` (key sizes 2048, 3072, 4096), `EC` (`P-256`, `P-384`, `P-521`, `SECP256K1`) | `oct` (Symmetric AES-256 in Managed HSM) |
| **Google Cloud KMS** | `RSA_SIGN_*`, `RSA_DECRYPT_*`, `EC_SIGN_*` | `GOOGLE_SYMMETRIC_ENCRYPTION` (AES-256) |

---

## 2. Auditing Terraform HCL Scripts

PQCanary directly parses Terraform configuration files (`.tf`) to flag vulnerable cloud KMS resources before infrastructure is provisioned:

```bash
pqcanary cloud-kms ./terraform/
```

### Example Vulnerable Terraform HCL

```hcl
resource "aws_kms_key" "app_encryption" {
  description              = "Application Signing Key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048" # VULNERABLE: Asymmetric RSA
  deletion_window_in_days  = 10
}
```

PQCanary detects this resource and produces:

```
HIGH: PQC-CLOUD-AWS-KMS-ASYM: aws_kms_key.app_encryption utilizes RSA_2048.
Vulnerable to Shor's algorithm and CNSA 2.0 obsolescence.
Remediation: Migrate to SYMMETRIC_DEFAULT or post-quantum hybrid algorithm.
```

---

## 3. Auditing AWS KMS via AWS CLI

Export key metadata from AWS KMS and pipe directly into `pqcanary cloud-kms`:

```bash
# Describe a specific AWS KMS key
aws kms describe-key --key-id 1234abcd-12ab-34cd-56ef-1234567890ab | pqcanary cloud-kms -

# Audit all keys in a region
for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
  echo "Auditing AWS KMS Key: $key_id"
  aws kms describe-key --key-id "$key_id" | pqcanary cloud-kms -
done
```

---

## 4. Auditing Azure Key Vault via Azure CLI

Export key properties from Azure Key Vault and audit:

```bash
# Export key from Azure Key Vault
az keyvault key show \
  --vault-name "prod-corp-vault" \
  --name "customer-data-key" | pqcanary cloud-kms -
```

---

## 5. Auditing Google Cloud KMS via gcloud

Inspect a Google Cloud KMS CryptoKey:

```bash
# Describe Cloud KMS key in Google Cloud
gcloud kms keys describe "prod-signing-key" \
  --keyring "app-keyring" \
  --location "us-central1" \
  --format=json | pqcanary cloud-kms -
```

---

## 6. CNSA 2.0 KMS Migration Timelines

Under NSA CNSA 2.0 mandates, cloud key management systems must adhere to strict deprecation schedules:
1. **2025**: Begin procurement and transition planning for post-quantum symmetric (AES-256) and lattice algorithms (ML-KEM-1024).
2. **2030**: Software and firmware signing keys must exclusively use ML-DSA or SLH-DSA.
3. **2031**: Classical asymmetric encryption keys (RSA, ECC) are completely prohibited in cloud key management.
