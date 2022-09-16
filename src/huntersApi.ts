if (!process.env.HUNTERS_API_CLIENT_ID) {
  throw new Error("HUNTERS_API_CLIENT_ID environment variable not set");
}
if (!process.env.HUNTERS_API_SECRET_KEY) {
  throw new Error("HUNTERS_API_SECRET_KEY environment variable not set");
}

const HUNTERS_API_CLIENT_ID = process.env.HUNTERS_API_CLIENT_ID;
const HUNTERS_API_SECRET_KEY = process.env.HUNTERS_API_SECRET_KEY;

export interface HuntersLead {
  uuid: string;
  event_time: string;
  score: number;
  source: string;
  status: string;
  risk: string;
  detection_time: string;
  detector: string;
  maliciousness: number;
  data_sources: string[];
  investigation_state: "in progress" | "completed" | "ignored";
}

export interface HuntersEntity {
  kind: string;
  name: string;
  value: string;
}

export interface HuntersME {
  lead_uuid: string;
  attributes: {
    [k: string]: {
      name: string;
      kind: string;
      value: string;
    };
  };
  entities: HuntersEntity[];
}

export class HuntersAPI {
  private accessToken: string = "";
  private refreshToken: string = "";

  async makeGetRequest(relativeUrl: string, body: any) {
    if (!this.accessToken) {
      await this.authenticate();
    }

    const url = `https://api.us.hunters.ai/v1/${relativeUrl}${
      body ? `?${new URLSearchParams(body)}` : ""
    }`;
    console.log(`Fetching ${url}`);

    const res = await fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.accessToken}`,
      },
    });

    if (!res.ok) {
      throw new Error(`${res.status}: ${res.statusText}`);
    }
    return res.json();
  }

  async authenticate() {
    console.log("Authenticating");
    const res = await fetch(`https://api.us.hunters.ai/v1/auth/api-token`, {
      body: JSON.stringify({
        clientId: HUNTERS_API_CLIENT_ID,
        secret: HUNTERS_API_SECRET_KEY,
      }),
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    });

    const body: { accessToken: string; refreshToken: string } =
      await res.json();
    this.accessToken = body.accessToken;
    this.refreshToken = body.refreshToken;
    console.log("Got refresh and access tokens");
  }

  async fetchFromUuids(uuids: string[]) {
    console.log("Fetching UUIDs");
    const res: { results: HuntersLead[] } = await this.makeGetRequest("leads", {
      uuid: uuids,
    });
    return res.results;
  }

  // just used for testing
  async fetchAllUUIDs() {
    const res: { results: HuntersLead[] } = await this.makeGetRequest(
      "leads",
      {}
    );
    return res.results;
  }

  async fetchMegaentities(uuids: string[]) {
    console.log("Fetching megaentities");

    const res: Array<{ results: HuntersME[] }> = await Promise.all(
      uuids.map(async (uuid) =>
        this.makeGetRequest(`mega-entities/${uuid}`, null)
      )
    );
    return res.map((r) => r.results);
  }
}

export const KindMapping = {
  hostname: [
    "hostname_array",
    "hostnames",
    "ip_or_hostname",
    "hostname_fqdn_array",
    "hostname",
    "hostname_fqdn",
  ],
  username: [
    "aws_username",
    "pan_username",
    "aws_user_identity_arn",
    "aws_user_arn",
    "domain_os_username",
    "local_os_username",
    "mac_user_id",
    "zscaler_user",
    "aws_user_identity_username",
    "windows_user_sid",
    "email_user_array",
    "o365_username",
    "cisco_amp_username",
    "checkpoint_username",
    "email_user",
    "okta_user_display_name",
    "ad_username",
  ],
  domain: ["domain", "domain_array", "domains", "domain_or_ip"],
  hash: ["hash_sha256_array", "hash_md5", "hash_sha1", "hash_sha256"],
  url: ["urls", "url", "url_array"],
  ip: ["array_ip", "ip_array", "ip_or_hostname", "ips", "ip", "domain_or_ip"],
};

const allKinds = [
  "file_path",
  "aws_username",
  "hostname_array",
  "pan_username",
  "display_name",
  "cisco_amp_agent_id",
  "person_name",
  "aws_user_identity_arn",
  "file_name_array",
  "cb_defense_email",
  "aws_instance_id_array",
  "hostnames",
  "hash_sha256_array",
  "macs",
  "urls",
  "windows_logon_type",
  "okta_device_type",
  "hash_md5",
  "windows_service_description",
  "array_ip",
  "commandline",
  "aws_error_message",
  "computer_serial_number",
  "okta_device_fingerprint",
  "aws_user_arn",
  "aws_response_elements",
  "wel_binary_path",
  "email_service_mailbox",
  "timestamps",
  "mac",
  "cb_policy_names",
  "ip_array",
  "threat_intel_group_id",
  "aws_account_id_array",
  "url",
  "okta_display_name",
  "okta_request_uri_with_parameters",
  "domain_os_username",
  "domain",
  "cs_pid",
  "aws_session_access_key_ids",
  "user_agents",
  "aws_service_domain",
  "windows_error_code",
  "binary_path",
  "cs_windows_process_integrity_level",
  "windows_package_name",
  "binary_path_array",
  "user_agent_array_user_agent",
  "windows_service_name",
  "zscaler_threat_name",
  "timestamp",
  "windows_logon_process",
  "cb_virus_subcategory",
  "cb_reputation",
  "cb_virus_name",
  "cb_policy_name",
  "windows_process_session_id",
  "aws_iam_policy_name",
  "aws_iam_group_name",
  "okta_behaviors_str",
  "local_os_username",
  "ip_or_hostname",
  "av_threat_signature_array",
  "aws_user_agents",
  "os_username",
  "aws_account_id",
  "username",
  "data_type",
  "aws_iam_role_name",
  "azure_subscription",
  "aws_instance_id",
  "fqdn",
  "azure_service_principal_array",
  "file_name",
  "okta_risk_str",
  "aws_arn",
  "aws_access_key_id",
  "domain_array",
  "ioc_tag",
  "http_substatus_code",
  "user_agent",
  "ioc_tag_array",
  "azure_upn",
  "aws_iam_access_denied_error_message",
  "http_substatus_code_array",
  "aws_vol_id",
  "outcome_result",
  "os_username_array",
  "osquery_instance_id",
  "sysmon_dns_response",
  "agent_pid",
  "cb_event_id",
  "cb_threat_id",
  "hash_sha1",
  "azure_tenant_id_array",
  "cb_platform_device_username",
  "win32_status_code",
  "int",
  "azure_correlation_id",
  "aws_user_identity_arn_array",
  "aws_sg_id",
  "upn",
  "gsuite_display_name",
  "aws_arn_session_name",
  "ad_username",
  "ips",
  "aws_subnet_id",
  "meraki_client_id",
  "meraki_network_id",
  "pan_location",
  "pan_rule_name",
  "pan_zone_name",
  "sysmon_process_guid",
  "aws_event_name",
  "fortinet_fw_action",
  "gsuite_device_id",
  "aws_account_ids",
  "azure_app_id",
  "azure_app_id_array",
  "azure_resource_id",
  "aws_ebs_snapshot_id",
  "countries",
  "domains",
  "cs_detection_id",
  "okta_browser",
  "okta_action_categories",
  "okta_action_type",
  "okta_os",
  "str",
  "okta_user_display_name",
  "protocols",
  "protocol",
  "specific_attrs",
  "aws_event_names",
  "specific_source_type",
  "email_user",
  "port_array",
  "cb_pid",
  "mdatp_agent_id",
  "cb_agent_id",
  "mdatp_pid",
  "cs_agent_id",
  "azure_display_name",
  "cisco_amp_username",
  "agent_id",
  "cb_incident_id",
  "checkpoint_username",
  "url_array",
  "o365_username",
  "azure_app_ids",
  "okta_app_instance_id",
  "raw_pid",
  "email_user_array",
  "email_mailbox_array",
  "email_mailbox",
  "av_threat_signature",
  "agari_policy_name_array",
  "gsuite_device_serial_number",
  "uri",
  "windows_user_sid",
  "azure_correlation_id_array",
  "azure_instance_credentials_id_array",
  "win32_status_code_array",
  "commandline_array",
  "aws_user_agent",
  "cb_event_type",
  "meraki_network_application",
  "hostname_fqdn_array",
  "azure_resource_id_array",
  "aws_user_identity_username",
  "aws_vpc_id",
  "azure_result_type",
  "domain_label",
  "fortinet_fw_device_id",
  "country",
  "ad_domain",
  "aws_guardduty_finding_arn",
  "binary_name",
  "binary_name_array",
  "zscaler_user",
  "email",
  "azure_display_name_array",
  "uri_array",
  "http_status_code_array",
  "sharepoint_object_uid",
  "agent_pid_array",
  "okta_request_uri",
  "port",
  "hostname",
  "hash_sha256",
  "directory_path",
  "ip",
  "mac_user_id",
  "http_status_code",
  "sharepoint_file_path",
  "windows_authentication_package",
  "agari_policy_name",
  "os_version",
  "ports",
  "aws_eni_id",
  "azure_tenant_id",
  "azure_service_principal",
  "azure_app_display_name",
  "dict",
  "aws_s3_key_prefix",
  "azure_device_detail",
  "azure_risk_detail",
  "aws_error_code",
  "azure_ad_id",
  "aws_request_parameters",
  "cb_device_priorities",
  "email_array",
  "array",
  "array_port",
  "bool",
  "aws_ssm_document_name",
  "aws_s3_bucket_name",
  "aws_role_session_name",
  "double",
  "fortinet_fw_interface",
  "fortinet_fw_name",
  "user_agent_array",
  "domain_or_ip",
  "hostname_fqdn",
  "luminate_event_status",
  "cb_device_priority",
  "aws_trail_arn",
  "azure_instance_credentials_id",
];
