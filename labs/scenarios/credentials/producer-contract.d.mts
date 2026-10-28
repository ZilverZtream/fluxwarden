/** Opaque I-owned setup/transport implementations live in scripts/, never here.
 * Upstream files are inert source inputs. No credential plaintext or observed/PASS claim is returned. */
export type NodeName = 'lnd-p' | 'lnd-r' | 'cln-p' | 'cln-r' | 'cln-m';
export interface EndpointRef { node: NodeName; transport: 'owned-node-https'; certificate: { node: NodeName }; roles: ['read', 'execute'] }
export interface SourceProducer {
  preparePinnedCredentialSources(input: { directory: string; checkouts: { macwarden: string; lnd: string; cln: string } }):
    Promise<{ referenceRoot: string; sourceManifest: string; bindingSourceManifest: string }>;
}
export interface BindingRequest {
  declaration: string; imagePins: Record<string, string>; endpointRefs: Record<NodeName, EndpointRef>;
  changePassword: { kind: 'fresh-denial-control' }; signal?: AbortSignal;
}
export interface Endpoint { hostname: string; servername: string; port: number; certificate: string; containerId: string }
export interface ContainerBinding {
  Id: string; Image: string;
  Config: { Image: string; Labels: { 'com.docker.compose.project': string; 'com.docker.compose.service': string } };
  NetworkSettings: { Networks: Record<string, { NetworkID: string; IPAddress: string }> };
}
export interface BoundOwner {
  version: 1; ownerId: string; project: string; declarationSha256: string; manifestSha256: string;
  endpoints: Record<NodeName, Endpoint>;
  credentials: Record<NodeName, Record<'read' | 'execute', { path: string; fingerprint: string }>>;
  changePasswordFile: string;
  /** Sanitized actual inspect fields only: no Config.Env, raw certificates or credentials. */
  containers: ContainerBinding[];
}
export interface BindingProducer { bindFreshCredentialOwner(input: BindingRequest): Promise<BoundOwner> }
