export interface RatlsFetchOptions {
  proxyUrl: string;
  targetHost: string;
  serverName?: string;
  defaultHeaders?: Record<string, string>;
  onAttestation?: (attestation: RatlsAttestation) => void;
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

export interface RatlsHeaderEntry {
  name: string;
  value: string;
}

export class RatlsClient {
  constructor(websocketUrl: string, serverName: string, hostHeader?: string);
  handshake(): Promise<RatlsAttestation>;
  attestation(): RatlsAttestation;
  httpRequest(
    method: string,
    pathAndQuery: string,
    headers: RatlsHeaderEntry[] | undefined,
    body?: Uint8Array
  ): Promise<RatlsResponse>;
  close(): Promise<void>;
}

export function createRatlsFetch(options: RatlsFetchOptions): (input: RequestInfo | URL, init?: RequestInit) => Promise<RatlsResponse>;
