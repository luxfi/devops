//! CloudFormation template management

use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Embedded CloudFormation templates
#[derive(RustEmbed)]
#[folder = "src/aws/cfn-templates/"]
pub struct CfnTemplates;

/// Get a CloudFormation template by name
pub fn get_template(name: &str) -> Option<String> {
    CfnTemplates::get(name).map(|f| String::from_utf8_lossy(f.data.as_ref()).to_string())
}

/// List all available templates
pub fn list_templates() -> Vec<String> {
    CfnTemplates::iter().map(|s| s.to_string()).collect()
}

/// Available template names
pub mod templates {
    pub const VPC: &str = "vpc.yaml";
    pub const EC2_INSTANCE_ROLE: &str = "ec2_instance_role.yaml";
    pub const ASG_UBUNTU: &str = "asg_ubuntu.yaml";
    pub const SSM_INSTALL_SUBNET_CHAIN: &str = "ssm_install_subnet_chain.yaml";
}

/// CloudFormation stack status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StackStatus {
    CreateInProgress,
    CreateFailed,
    CreateComplete,
    RollbackInProgress,
    RollbackFailed,
    RollbackComplete,
    DeleteInProgress,
    DeleteFailed,
    DeleteComplete,
    UpdateInProgress,
    UpdateCompleteCleanupInProgress,
    UpdateComplete,
    UpdateFailed,
    UpdateRollbackInProgress,
    UpdateRollbackFailed,
    UpdateRollbackCompleteCleanupInProgress,
    UpdateRollbackComplete,
    ReviewInProgress,
    ImportInProgress,
    ImportComplete,
    ImportRollbackInProgress,
    ImportRollbackFailed,
    ImportRollbackComplete,
}

impl StackStatus {
    /// Check if the stack is in a terminal success state
    pub fn is_complete(&self) -> bool {
        matches!(
            self,
            Self::CreateComplete | Self::UpdateComplete | Self::ImportComplete
        )
    }

    /// Check if the stack is in a terminal failure state
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::CreateFailed
                | Self::RollbackFailed
                | Self::RollbackComplete
                | Self::DeleteFailed
                | Self::UpdateFailed
                | Self::UpdateRollbackFailed
                | Self::UpdateRollbackComplete
                | Self::ImportRollbackFailed
                | Self::ImportRollbackComplete
        )
    }

    /// Check if the stack is in a deleted state
    pub fn is_deleted(&self) -> bool {
        matches!(self, Self::DeleteComplete)
    }

    /// Check if an operation is in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            Self::CreateInProgress
                | Self::RollbackInProgress
                | Self::DeleteInProgress
                | Self::UpdateInProgress
                | Self::UpdateCompleteCleanupInProgress
                | Self::UpdateRollbackInProgress
                | Self::UpdateRollbackCompleteCleanupInProgress
                | Self::ReviewInProgress
                | Self::ImportInProgress
                | Self::ImportRollbackInProgress
        )
    }
}

/// CloudFormation parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackParameter {
    pub key: String,
    pub value: String,
}

impl StackParameter {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// CloudFormation output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackOutput {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
}

/// Stack creation options
#[derive(Debug, Clone)]
pub struct CreateStackOptions {
    pub stack_name: String,
    pub template_body: String,
    pub parameters: Vec<StackParameter>,
    pub capabilities: Vec<String>,
    pub tags: HashMap<String, String>,
    pub on_failure: OnFailure,
    pub timeout_minutes: Option<i32>,
}

/// What to do if stack creation fails
#[derive(Debug, Clone, Copy, Default)]
pub enum OnFailure {
    #[default]
    Rollback,
    Delete,
    DoNothing,
}

impl OnFailure {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rollback => "ROLLBACK",
            Self::Delete => "DELETE",
            Self::DoNothing => "DO_NOTHING",
        }
    }
}

impl CreateStackOptions {
    /// Create new options with required fields
    pub fn new(stack_name: impl Into<String>, template_body: impl Into<String>) -> Self {
        Self {
            stack_name: stack_name.into(),
            template_body: template_body.into(),
            parameters: Vec::new(),
            capabilities: Vec::new(),
            tags: HashMap::new(),
            on_failure: OnFailure::default(),
            timeout_minutes: None,
        }
    }

    /// Add a parameter
    pub fn with_parameter(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.push(StackParameter::new(key, value));
        self
    }

    /// Add IAM capability (required for stacks that create IAM resources)
    pub fn with_iam_capability(mut self) -> Self {
        self.capabilities.push("CAPABILITY_IAM".to_string());
        self
    }

    /// Add named IAM capability
    pub fn with_named_iam_capability(mut self) -> Self {
        self.capabilities.push("CAPABILITY_NAMED_IAM".to_string());
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Set on-failure behavior
    pub fn with_on_failure(mut self, on_failure: OnFailure) -> Self {
        self.on_failure = on_failure;
        self
    }

    /// Set timeout
    pub fn with_timeout_minutes(mut self, minutes: i32) -> Self {
        self.timeout_minutes = Some(minutes);
        self
    }
}

/// VPC stack parameters
#[derive(Debug, Clone)]
pub struct VpcStackParams {
    pub id: String,
    pub user_id: String,
    pub ssh_ingress_cidr: String,
    pub http_ingress_cidr: String,
    pub http_port: u16,
    pub staking_ingress_cidr: String,
    pub staking_port: u16,
}

impl VpcStackParams {
    pub fn new(id: impl Into<String>, user_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            user_id: user_id.into(),
            ssh_ingress_cidr: "0.0.0.0/0".to_string(),
            http_ingress_cidr: "0.0.0.0/0".to_string(),
            http_port: 9650,
            staking_ingress_cidr: "0.0.0.0/0".to_string(),
            staking_port: 9651,
        }
    }

    /// Build CreateStackOptions for this VPC
    pub fn to_create_options(&self) -> CreateStackOptions {
        let template = get_template(templates::VPC).expect("VPC template must be embedded");

        CreateStackOptions::new(format!("{}-vpc", self.id), template)
            .with_parameter("Id", &self.id)
            .with_parameter("UserId", &self.user_id)
            .with_parameter("SshPortIngressIpv4Range", &self.ssh_ingress_cidr)
            .with_parameter("HttpPortIngressIpv4Range", &self.http_ingress_cidr)
            .with_parameter("HttpPort", self.http_port.to_string())
            .with_parameter("StakingPortIngressIpv4Range", &self.staking_ingress_cidr)
            .with_parameter("StakingPort", self.staking_port.to_string())
            .with_tag("lux-ops:cluster-id", &self.id)
    }
}

/// EC2 instance role stack parameters
#[derive(Debug, Clone)]
pub struct InstanceRoleStackParams {
    pub id: String,
    pub role_name: String,
    pub role_profile_name: String,
    pub kms_key_arn: String,
    pub s3_bucket_name: String,
}

impl InstanceRoleStackParams {
    pub fn new(
        id: impl Into<String>,
        kms_key_arn: impl Into<String>,
        s3_bucket_name: impl Into<String>,
    ) -> Self {
        let id = id.into();
        Self {
            role_name: format!("{}-instance-role", id),
            role_profile_name: format!("{}-instance-profile", id),
            id,
            kms_key_arn: kms_key_arn.into(),
            s3_bucket_name: s3_bucket_name.into(),
        }
    }

    /// Build CreateStackOptions for this instance role
    pub fn to_create_options(&self) -> CreateStackOptions {
        let template =
            get_template(templates::EC2_INSTANCE_ROLE).expect("EC2 instance role template must be embedded");

        CreateStackOptions::new(format!("{}-instance-role", self.id), template)
            .with_parameter("Id", &self.id)
            .with_parameter("RoleName", &self.role_name)
            .with_parameter("RoleProfileName", &self.role_profile_name)
            .with_parameter("KmsKeyArn", &self.kms_key_arn)
            .with_parameter("S3BucketName", &self.s3_bucket_name)
            .with_named_iam_capability()
            .with_tag("lux-ops:cluster-id", &self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_template() {
        let vpc = get_template(templates::VPC);
        assert!(vpc.is_some(), "VPC template should be embedded");
        let vpc = vpc.unwrap();
        assert!(
            vpc.contains("AWSTemplateFormatVersion"),
            "Should be valid CloudFormation template"
        );
    }

    #[test]
    fn test_list_templates() {
        let templates_list = list_templates();
        assert!(templates_list.contains(&templates::VPC.to_string()));
        assert!(templates_list.contains(&templates::EC2_INSTANCE_ROLE.to_string()));
    }

    #[test]
    fn test_stack_status_states() {
        assert!(StackStatus::CreateComplete.is_complete());
        assert!(StackStatus::CreateFailed.is_failed());
        assert!(StackStatus::DeleteComplete.is_deleted());
        assert!(StackStatus::CreateInProgress.is_in_progress());
    }

    #[test]
    fn test_vpc_stack_params() {
        let params = VpcStackParams::new("test-cluster", "user-123");
        let options = params.to_create_options();

        assert_eq!(options.stack_name, "test-cluster-vpc");
        assert!(!options.template_body.is_empty());
        assert!(options
            .parameters
            .iter()
            .any(|p| p.key == "Id" && p.value == "test-cluster"));
    }

    #[test]
    fn test_instance_role_stack_params() {
        let params =
            InstanceRoleStackParams::new("test-cluster", "arn:aws:kms:...", "my-bucket");
        let options = params.to_create_options();

        assert_eq!(options.stack_name, "test-cluster-instance-role");
        assert!(options.capabilities.contains(&"CAPABILITY_NAMED_IAM".to_string()));
    }

    #[test]
    fn test_create_stack_options_builder() {
        let options = CreateStackOptions::new("my-stack", "template body")
            .with_parameter("Param1", "Value1")
            .with_iam_capability()
            .with_tag("Environment", "test")
            .with_on_failure(OnFailure::Delete)
            .with_timeout_minutes(30);

        assert_eq!(options.stack_name, "my-stack");
        assert_eq!(options.parameters.len(), 1);
        assert!(options.capabilities.contains(&"CAPABILITY_IAM".to_string()));
        assert_eq!(options.tags.get("Environment"), Some(&"test".to_string()));
        assert_eq!(options.timeout_minutes, Some(30));
    }
}
