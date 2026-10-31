export interface DomainRule { kind: string; domain: string; action: string }
export interface SteroidConfig { pacPort: number; rules: DomainRule[] }
export interface DomainEvent { domain: string; action: string; connections: number; lastSeen: number; error: string }
export interface Preferences {
  theme: string;
  speedVisualization: string;
  remainingVisualization: string;
  totalsVisualization: string;
  latencyRefreshSeconds: number;
}
export const defaultPreferences: Preferences = {theme:'midnight',speedVisualization:'graph',remainingVisualization:'ring',totalsVisualization:'bars',latencyRefreshSeconds:30};
export interface Location { code: string; name: string; pingMs: number; pingCheckedAt: number }
export interface Account { email: string; quotaLimit: number; quotaRemaining: number; quotaCheckedAt: number; quotaError: string }
export interface State {
 steroidConfig: SteroidConfig; observedDomains: DomainEvent[]; directIp: string; directUpload: number; directDownload: number;
 preferences: Preferences;
 accounts: Account[]; pendingEmail: string; socksPort: number; httpPort: number;
  status: string; signedIn: boolean; needsCode: boolean; email: string;
  locations: Location[]; country: string; mode: string; ip: string; since: number;
  serverPingsChecking: boolean; serverPingsCompleted: number; serverPingsTotal: number; serverPingsCheckedAt: number; serverPingsError: string;
  upload: number; download: number; quotaLimit: number; quotaRemaining: number;
  uploadSpeed: number; downloadSpeed: number; latencyMs: number; latencyCheckedAt: number; latencyChecking: boolean; latencyError: string;
  error: string; notice: string;
}
export interface Backend {
  GetState(): Promise<State>;
  Login(email: string, password: string): Promise<void>;
  Verify(code: string): Promise<void>;
  CancelVerification(): Promise<void>;
  RefreshLocations(): Promise<void>;
  RefreshServerPings(): Promise<void>;
  Connect(country: string, mode: string): Promise<void>;
  Disconnect(): Promise<void>;
  SignOut(): Promise<void>;
  SwitchAccount(email: string): Promise<void>;
  RemoveAccount(email: string): Promise<void>;
  RefreshAccountQuota(email: string): Promise<void>;
  MeasureLatency(): Promise<void>;
  SavePorts(socks: number, http: number): Promise<void>;
  SavePreferences(preferences: Preferences): Promise<void>;
  SaveSteroidConfig(config: SteroidConfig): Promise<void>;
  ClearObservedDomains(): Promise<void>;
}
declare global { interface Window { go?: { main: { App: Backend } } } }
export function backend(): Backend {
  if (!window.go?.main?.App) throw new Error('Open the NAT-on-steroids desktop app to sign in and connect. This browser preview cannot start a VPN.');
  return window.go.main.App;
}
