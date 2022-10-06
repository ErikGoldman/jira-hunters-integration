import { HuntersAPI, HuntersME, KindMapping } from "./huntersApi";
import {
  flattenDescriptionText,
  GetFieldID,
  getTicketsToEnrich,
  getTicketsWithoutUUID,
  getUnsetTicketsInProject,
  JiraTicketResponse,
  setIssueFields,
} from "./jiraApi";

const REFRESH_INTERVAL = 1000 * 60 * 5;

/*
Detection Tool: Hunters
Other Detection tool: data source
Event happened : Actual event happen time as per data source or Hunters hunt.
Event Detected: Time at which Hunters alert/lead/story was created.
Severity : Use this only for High and criticals, and set to P2. For everything else, its P4 on my end.

Configuration Item: hostname
Affected user: username
IOC-Hash - SHA256 value if available (EDR, Mimecast, etc) - should have comma separated values in case more than 1
IOC-Domain/URL - should have comma separated values in case more than 1
IOC-IPAddress - should have comma separated values in case more than 1
*/

const FIELDS = {
  DETECTION_TOOL: "Detection Tool",
  OTHER_DETECTION_TOOL: "Other Detection tool",
  EVENT_HAPPENED: "Event happened",
  EVENT_DETECTED: "Event Detected",
  SEVERITY: "Severity",
  INVESTIGATION_STATE_FIELD: "Investigation state",
  HAS_ENRICHED_FIELD: "Has enriched",
  UUID: "UUID",

  CONFIGURATION_ITEM: "Configuration Item",
  AFFECTED_USER: "Affected user",
  IOC_HASH: "IOC-Hash",
  IOC_DOMAIN: "IOC-Domain",
  IOC_URL: "IOC-URL",
  IOC_IP: "IOC-IPAddress",
};

const huntersApi = new HuntersAPI();

export function InvertJiraFieldMapping(names: { [k: string]: string }) {
  const JiraBasicFieldMapping: { [k: string]: string } = {};
  Object.values(FIELDS).forEach((field) => {
    const fieldId = GetFieldID(names, field);
    if (!fieldId) {
      throw new Error(`Could not find Jira field ${field}`);
    }
    JiraBasicFieldMapping[field] = fieldId;
  });
  return JiraBasicFieldMapping;
}

function GetUUIDsToProcess(
  jiraTickets: JiraTicketResponse
): [Array<[string, string]>, { [fieldName: string]: string }] {
  if (!jiraTickets.issues || jiraTickets.issues.length === 0) {
    return [[], {}];
  }

  const uuidFieldId = GetFieldID(jiraTickets.names, FIELDS.UUID);
  if (!uuidFieldId) {
    throw new Error("Could not find UUID field ID");
  }
  const uuidList: Array<[string, string]> = jiraTickets.issues.map((issue) => [
    issue.id,
    issue.fields[uuidFieldId] as string,
  ]);
  console.log(`Got UUIDs ${JSON.stringify(uuidList)}`);

  if (uuidList.length === 0) {
    return [[], {}];
  }

  if (uuidList.length === 0) {
    console.log("No uuids to process");
  }
  return [uuidList, InvertJiraFieldMapping(jiraTickets.names)];
}

function logSourceToJiraDetectionTool(logSource: string): string {
  const validTools: { [k: string]: string } = {
    "Atlassian Audit": "atlassian",
    AWS: "aws",
    "Cisco Meraki": "meraki",
    Cloudflare: "cloudflare",
    "Crowdstrike EDR": "crowdstrike",
    GitHub: "github",
    Intune: "intune",
    Lacework: "lacework",
    Mimecast: "mimecast",
    Netskope: "netskope",
    NOS: "nos",
    O365: "o365",
    Okta: "okta",
    RiskSense: "risksense",
    Sophos: "sophos",
  };

  const normalized = logSource.toLocaleLowerCase().trim();
  const foundValue = Object.keys(validTools)
    .map((k) => {
      if (normalized.includes(validTools[k])) {
        return k;
      }
      return undefined;
    })
    .find((x) => x);

  if (foundValue) {
    return foundValue;
  }

  return "Other";
}

async function RunBasic() {
  console.log("Fetching basic unset Jira tickets");
  const jiraTicketsBasic = await getUnsetTicketsInProject(
    FIELDS.INVESTIGATION_STATE_FIELD,
    FIELDS.UUID
  );

  const [uuidList, JiraBasicFieldMapping] = GetUUIDsToProcess(jiraTicketsBasic);
  const huntersUUids = uuidList.map((uuidTuple) => uuidTuple[1]);

  if (huntersUUids.length === 0) {
    console.log("No basic UUIDs");
    return;
  }

  console.log(
    `Fetching Hunters UUIDs for basic fields: ${JSON.stringify(huntersUUids)}`
  );
  const huntersLeads = await huntersApi.fetchFromUuids(huntersUUids);

  const data = huntersLeads.map((lead) => {
    const matchingJiraId = uuidList.find((tuple) => tuple[1] === lead.uuid);
    if (!matchingJiraId) {
      throw new Error(`Could not find ${lead.uuid} in Jira list`);
    }
    return {
      issueID: parseInt(matchingJiraId[0], 10),
      fields: {
        [JiraBasicFieldMapping[FIELDS.DETECTION_TOOL]]: { value: "Hunters" },
        [JiraBasicFieldMapping[FIELDS.OTHER_DETECTION_TOOL]]: {
          value: logSourceToJiraDetectionTool(lead.source),
        },
        [JiraBasicFieldMapping[FIELDS.EVENT_HAPPENED]]: lead.event_time,
        [JiraBasicFieldMapping[FIELDS.EVENT_DETECTED]]: lead.detection_time,
        [JiraBasicFieldMapping[FIELDS.SEVERITY]]: {
          value:
            lead.risk === "high" || lead.risk === "critical"
              ? "P2-Major"
              : "P4-Trivial",
        },
        [JiraBasicFieldMapping[FIELDS.INVESTIGATION_STATE_FIELD]]:
          lead.investigation_state,
      },
    };
  });

  await setIssueFields(data);
}

function getMEValueOrEmpty(
  meResponse: HuntersME[],
  highLevelKind: keyof typeof KindMapping
) {
  const matchingAttributes = meResponse
    .map((me) =>
      Object.values(me.attributes).map((attr) =>
        attr && KindMapping[highLevelKind].find((k) => k === attr.kind)
          ? me.attributes[attr.name].value
          : undefined
      )
    )
    .flat()
    .filter((x) => x) as string[];
  if (matchingAttributes.length === 0) {
    return "";
  }
  return matchingAttributes.join(",");
}

async function RunEnrichment() {
  console.log("Fetching enrichment unset Jira tickets");
  const jiraTickets = await getTicketsToEnrich(
    FIELDS.INVESTIGATION_STATE_FIELD,
    FIELDS.HAS_ENRICHED_FIELD,
    FIELDS.UUID
  );

  const [uuidList, JiraFieldMapping] = GetUUIDsToProcess(jiraTickets);
  const huntersUUids = uuidList.map((uuidTuple) => uuidTuple[1]);

  if (huntersUUids.length === 0) {
    console.log("No enrichment UUIDs");
    return;
  }

  console.log(
    `Fetching Hunters megaentities for enrichment fields: ${JSON.stringify(
      huntersUUids
    )}`
  );
  const huntersMEs = await huntersApi.fetchMegaentities(huntersUUids);

  const data = huntersMEs
    .filter((x) => x && x[0])
    .map((me) => {
      const matchingJiraId = uuidList.find(
        (tuple) => tuple[1] === me[0].lead_uuid
      );
      if (!matchingJiraId) {
        throw new Error(`Could not find ${me[0].lead_uuid} in Jira list`);
      }

      const fields: { [k: string]: string } = {};
      if (me && me.length !== 0) {
        console.log(
          `Got ME attributes for ${me[0].lead_uuid}: ${JSON.stringify(
            me.map((m) => m.attributes),
            null,
            2
          )}`
        );
        fields[JiraFieldMapping[FIELDS.CONFIGURATION_ITEM]] = getMEValueOrEmpty(
          me,
          "hostname"
        );
        fields[JiraFieldMapping[FIELDS.AFFECTED_USER]] = getMEValueOrEmpty(
          me,
          "username"
        );
        fields[JiraFieldMapping[FIELDS.IOC_DOMAIN]] = getMEValueOrEmpty(
          me,
          "domain"
        );
        fields[JiraFieldMapping[FIELDS.IOC_HASH]] = getMEValueOrEmpty(
          me,
          "hash"
        );
        fields[JiraFieldMapping[FIELDS.IOC_URL]] = getMEValueOrEmpty(me, "url");
        fields[JiraFieldMapping[FIELDS.IOC_IP]] = getMEValueOrEmpty(me, "ip");
      }
      fields[JiraFieldMapping[FIELDS.HAS_ENRICHED_FIELD]] = "true";

      return {
        issueID: parseInt(matchingJiraId[0], 10),
        fields,
      };
    });

  await setIssueFields(data);
}

// just for testing
async function GetInterestingUUIDs() {
  const leads = await huntersApi.fetchAllUUIDs();
  const MEs = await huntersApi.fetchMegaentities(
    leads.slice(5, 35).map((lead) => lead.uuid)
  );
  return MEs.filter((me) =>
    me.find((e) => Object.values(e.attributes).find((a) => a.value))
  )
    .filter((x) => x)
    .map((m) => m[0].lead_uuid);
}

const UUID_REGEX =
  /([0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12})/;

async function RunUUID() {
  console.log("Getting tickets without UUID");
  const ticketsWithoutUUID = await getTicketsWithoutUUID(FIELDS.UUID);
  if (ticketsWithoutUUID.issues.length === 0) {
    console.log("No tickets without UUID");
    return;
  }

  const fieldMapping = InvertJiraFieldMapping(ticketsWithoutUUID.names);
  const uuidField = fieldMapping[FIELDS.UUID];

  const uuids = ticketsWithoutUUID.issues.map((ish) => {
    const ticketDescription = flattenDescriptionText(ish.fields.description);
    console.log(
      `Flattened ${JSON.stringify(
        ish.fields.description
      )} to ${ticketDescription}`
    );

    let possibleUUIDs = ticketDescription.filter((s) => UUID_REGEX.test(s));
    if (possibleUUIDs.length > 1) {
      console.log(`Got multiple potential UUIDs for ${ish.id}`);
      possibleUUIDs = possibleUUIDs.filter(
        (s) => s.toLowerCase().indexOf("uuid") !== -1
      );
    }

    if (possibleUUIDs.length === 0) {
      console.error(`Could not match a UUID for ${ish.id}`);
      return { issueID: parseInt(ish.id, 10), fields: {} };
    }

    const match = possibleUUIDs[0].match(UUID_REGEX);
    if (!match) {
      console.error(`Couldn't get a match for regex on ${ish.id}`);
      return { issueID: parseInt(ish.id, 10), fields: {} };
    }
    return {
      issueID: parseInt(ish.id, 10),
      fields: { [uuidField]: match[1] },
    };
  });

  await setIssueFields(uuids);
}

async function main() {
  while (true) {
    await RunUUID();
    await RunBasic();
    await RunEnrichment();

    console.log("Sleeping...");
    await new Promise<void>((resolve, reject) => {
      setInterval(resolve, REFRESH_INTERVAL);
    });
    console.log("Waking up...");
  }
}

main().catch((e) => console.error(e));
