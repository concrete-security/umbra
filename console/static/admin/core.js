window.Admin = {
  STORAGE_KEY: "concrete_admin_session",
  ENTITY_KEY: "concrete_admin_entity",
  OPS_KEY: "concrete_admin_ops",
  OAUTH_CLIENT_ID: "umbra-cli-v1",
  PKCE_KEY: "concrete_admin_pkce",
  P: {
    PLATFORM: "PLATFORM_OPERATOR",
    AUDIT: "AUDIT_VIEW",
    TRAFFIC: "TRAFFIC_LOGS_VIEW",
    CVM_MANAGE: "CVM_MANAGE",
    CVM_LAUNCH: "CVM_LAUNCH",
    USER_MANAGE: "USER_MANAGE",
    SC_CONFIG: "SECURITY_CVM_CONFIGURE",
    PERM_MANAGE: "PERMISSION_MANAGE",
    QUOTA_MANAGE: "QUOTA_MANAGE",
    AUDIT_EXPORT: "AUDIT_EXPORT",
  },
  ENTITY_PERMS: [
    "CVM_LAUNCH",
    "CVM_MANAGE",
    "SECURITY_CVM_CONFIGURE",
    "TRAFFIC_LOGS_VIEW",
    "AUDIT_VIEW",
    "AUDIT_EXPORT",
    "USER_MANAGE",
    "PERMISSION_MANAGE",
    "QUOTA_MANAGE",
  ],
  DASHBOARD_PERMS: [
    "PLATFORM_OPERATOR",
    "AUDIT_VIEW",
    "TRAFFIC_LOGS_VIEW",
    "CVM_MANAGE",
    "CVM_LAUNCH",
    "USER_MANAGE",
    "SECURITY_CVM_CONFIGURE",
    "PERMISSION_MANAGE",
  ],
  session: null,
  ctx: null,
  activeTab: "overview",
  pollTimer: null,
  logAbort: null,
  selectedProfileId: null,
  selectedCvm: null,
  selectedSc: null,
  drawerKind: null,
  drawerTab: "egress",
  entitiesCache: [],
  fleetFilter: "all",
  fleetSearch: "",
  trafficWindow: "",
  trafficFrom: "",
  auditFilterAction: "",
  egressFilters: { host: "", code: "", window: "15m" },
  egressCursor: null,
  trafficCursor: null,
  auditCursor: null,
  entityScCache: null,
  POLL_MS: 10000,
  pollBackoffUntil: 0,
  refreshInFlight: false,
  pollSnapshot: null,

  el(id) {
    return document.getElementById(id);
  },

  has(perm) {
    return (this.ctx?.perms || []).includes(perm);
  },

  isPlatform() {
    return this.has(this.P.PLATFORM);
  },

  viewEntityId() {
    return this.ctx?.viewEntityId || this.ctx?.me?.entity?.id || this.ctx?.me?.entity_id;
  },

  isHomeEntity() {
    const homeId = this.ctx?.me?.entity?.id || this.ctx?.me?.entity_id;
    return this.ctx && this.viewEntityId() === homeId;
  },

  canManageProfiles() {
    return this.has(this.P.USER_MANAGE);
  },

  canActOnCvms() {
    return this.isHomeEntity() && (this.has(this.P.CVM_MANAGE) || this.has(this.P.CVM_LAUNCH));
  },
};
