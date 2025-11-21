export interface RatlsFetchOptions {
  proxyUrl: string;
  targetHost: string;
  serverName?: string;
  defaultHeaders?: Record<string, string>;
}

export interface RatlsAttestation {
  trusted: boolean;
  teeType: string;
  measurement?: string | null;
  tcbStatus: string;
  advisoryIds: string[];
}

export interface RatlsResponse extends Response {
  readonly ratlsAttestation?: RatlsAttestation;
}

export function createRatlsFetch(options: RatlsFetchOptions): (input: RequestInfo | URL, init?: RequestInit) => Promise<RatlsResponse>;
