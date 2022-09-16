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
}

export class HuntersAPI {
  private accessToken: string = "";
  private refreshToken: string = "";

  async makeRequest(url: string, body: any) {
    if (!this.accessToken) {
      await this.authenticate();
    }

    const res = await fetch(
      `https://api.us.hunters.ai/v1/${url}?${new URLSearchParams(body)}`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.accessToken}`,
        },
      }
    );

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

  async fetchUuids(uuids: string[]) {
    console.log("Fetching UUIDs");
    const res: { results: HuntersLead[] } = await this.makeRequest("leads", {
      uuid: uuids,
    });
    return res.results;
  }
}
