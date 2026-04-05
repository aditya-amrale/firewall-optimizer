import { useState, useEffect, useRef, useCallback } from "react";

// ─── Palette & design tokens ─────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500;600&display=swap');

  :root {
    --bg0: #0b0d11;
    --bg1: #10131a;
    --bg2: #161b26;
    --bg3: #1e2535;
    --border: rgba(255,255,255,0.07);
    --border-h: rgba(255,255,255,0.14);
    --text-pri: #e8eaf0;
    --text-sec: #7a8299;
    --text-dim: #404761;
    --red:    #f05252;
    --red-bg: rgba(240,82,82,0.1);
    --amber:  #f59e0b;
    --amb-bg: rgba(245,158,11,0.1);
    --yellow: #facc15;
    --yel-bg: rgba(250,204,21,0.09);
    --green:  #34d399;
    --grn-bg: rgba(52,211,153,0.09);
    --blue:   #60a5fa;
    --blu-bg: rgba(96,165,250,0.09);
    --mono: 'DM Mono', monospace;
    --sans: 'DM Sans', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg0); font-family: var(--sans); color: var(--text-pri); }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg1); }
  ::-webkit-scrollbar-thumb { background: var(--bg3); border-radius: 2px; }
`;

// ─── Sample data (mirrors real pipeline output) ───────────────────────────────
const SAMPLE_REPORT = {
  generated_at: new Date().toISOString(),
  summary: { total_rules: 12, total_recommendations: 9, critical_count: 3, high_count: 2 },
  rules: [
    { rule_id:"catch_all_allow", priority:5,  src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:null, protocol:"all", action:"ALLOW", comment:null,              hit_count:0 },
    { rule_id:"deny_rfc1918",    priority:10, src_ip:"10.0.0.0/8",   dst_ip:"0.0.0.0/0",    dst_port:null, protocol:"all", action:"DENY",  comment:null,              hit_count:0 },
    { rule_id:"allow_ssh_mgmt",  priority:20, src_ip:"10.10.0.0/16", dst_ip:"0.0.0.0/0",    dst_port:"22", protocol:"tcp", action:"ALLOW", comment:"Mgmt SSH",        hit_count:127 },
    { rule_id:"allow_ssh_dup",   priority:30, src_ip:"10.10.0.0/16", dst_ip:"0.0.0.0/0",    dst_port:"22", protocol:"tcp", action:"ALLOW", comment:null,              hit_count:0 },
    { rule_id:"allow_http",      priority:40, src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:"80", protocol:"tcp", action:"ALLOW", comment:"HTTP public",     hit_count:3842 },
    { rule_id:"allow_https",     priority:50, src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:"443",protocol:"tcp", action:"ALLOW", comment:"HTTPS public",    hit_count:5211 },
    { rule_id:"allow_dns",       priority:60, src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:"53", protocol:"udp", action:"ALLOW", comment:"DNS",             hit_count:1463 },
    { rule_id:"allow_ntp",       priority:70, src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:"123",protocol:"udp", action:"ALLOW", comment:"NTP",             hit_count:224 },
    { rule_id:"db_internal",     priority:80, src_ip:"10.0.0.0/8",   dst_ip:"10.0.1.0/24",  dst_port:"3306",protocol:"tcp",action:"ALLOW", comment:"MySQL internal",  hit_count:891 },
    { rule_id:"redis_internal",  priority:90, src_ip:"10.0.0.0/8",   dst_ip:"10.0.1.0/24",  dst_port:"6379",protocol:"tcp",action:"ALLOW", comment:"Redis internal",  hit_count:543 },
    { rule_id:"deny_smb",        priority:95, src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:"445",protocol:"tcp", action:"DENY",  comment:"Block SMB",       hit_count:38 },
    { rule_id:"deny_all",        priority:99, src_ip:"0.0.0.0/0",    dst_ip:"0.0.0.0/0",    dst_port:null, protocol:"all", action:"DENY",  comment:"Default deny",    hit_count:312 },
  ],
  findings: [
    { type:"CONTRADICTION", severity:"CRITICAL", rule_a:"catch_all_allow", rule_b:"deny_rfc1918",   reason:"catch_all_allow (ALLOW) covers every packet deny_rfc1918 (DENY) would match. The DENY never fires." },
    { type:"CONTRADICTION", severity:"CRITICAL", rule_a:"catch_all_allow", rule_b:"deny_smb",       reason:"catch_all_allow (ALLOW) fires before deny_smb (DENY) for all SMB traffic. Port 445 is never blocked." },
    { type:"CONTRADICTION", severity:"CRITICAL", rule_a:"catch_all_allow", rule_b:"deny_all",       reason:"catch_all_allow (ALLOW) shadows the default deny entirely. No packet ever reaches deny_all." },
    { type:"SHADOW",        severity:"HIGH",     rule_a:"catch_all_allow", rule_b:"allow_ssh_mgmt", reason:"allow_ssh_mgmt is dead code — catch_all_allow (priority 5) already allows all TCP traffic." },
    { type:"DUPLICATE",     severity:"MEDIUM",   rule_a:"allow_ssh_mgmt",  rule_b:"allow_ssh_dup",  reason:"allow_ssh_dup is structurally identical to allow_ssh_mgmt. Both match 10.10.0.0/16 → :22/tcp ALLOW." },
    { type:"PERMISSIVE",    severity:"MEDIUM",   rule_a:"catch_all_allow",  rule_b:"catch_all_allow", reason:"catch_all_allow permits ALL traffic from any source to any destination on any port." },
    { type:"SHADOW",        severity:"HIGH",     rule_a:"catch_all_allow", rule_b:"allow_http",     reason:"allow_http is unreachable — catch_all_allow already permits port 80 traffic." },
    { type:"SHADOW",        severity:"HIGH",     rule_a:"catch_all_allow", rule_b:"allow_https",    reason:"allow_https is unreachable — catch_all_allow already permits port 443 traffic." },
  ],
  recommendations: [
    { rec_id:"REC-0001", severity:"CRITICAL", fix_type:"REVIEW_RULE",      effort:"HIGH",   impact_score:9.8, title:"Resolve: catch_all_allow contradicts deny_rfc1918, deny_smb, deny_all",     suggestion:"Remove or narrow catch_all_allow. Replace with specific ALLOW rules for known-good ports, then add a default deny." },
    { rec_id:"REC-0002", severity:"HIGH",     fix_type:"ADD_DEFAULT_DENY",  effort:"LOW",   impact_score:8.5, title:"Add explicit default-deny as the final rule",                               suggestion:"Add: src=0.0.0.0/0, dst=0.0.0.0/0, port=any, action=DENY as the last rule." },
    { rec_id:"REC-0003", severity:"HIGH",     fix_type:"REMOVE_RULE",       effort:"LOW",   impact_score:7.5, title:"Remove shadowed rule allow_ssh_mgmt",                                       suggestion:"Delete allow_ssh_mgmt — it is never evaluated due to catch_all_allow at priority 5." },
    { rec_id:"REC-0004", severity:"HIGH",     fix_type:"REMOVE_RULE",       effort:"LOW",   impact_score:7.2, title:"Remove shadowed rule allow_http",                                           suggestion:"Delete allow_http — it is unreachable behind catch_all_allow." },
    { rec_id:"REC-0005", severity:"HIGH",     fix_type:"REMOVE_RULE",       effort:"LOW",   impact_score:7.0, title:"Remove shadowed rule allow_https",                                          suggestion:"Delete allow_https — it is unreachable behind catch_all_allow." },
    { rec_id:"REC-0006", severity:"MEDIUM",   fix_type:"NARROW_RULE",       effort:"MEDIUM",impact_score:5.2, title:"Narrow catch_all_allow to specific ports",                                  suggestion:"Replace with individual ALLOW rules for ports 80, 443, 53, 123, 22 (mgmt-only), 3306, 6379." },
    { rec_id:"REC-0007", severity:"MEDIUM",   fix_type:"REMOVE_RULE",       effort:"LOW",   impact_score:4.0, title:"Remove duplicate allow_ssh_dup",                                            suggestion:"Delete allow_ssh_dup — identical to allow_ssh_mgmt." },
    { rec_id:"REC-0008", severity:"LOW",      fix_type:"REORDER_RULE",      effort:"LOW",   impact_score:3.5, title:"Move allow_https before allow_http (higher traffic volume)",                suggestion:"allow_https gets 5211 hits vs allow_http 3842. Move HTTPS to priority 40." },
    { rec_id:"REC-0009", severity:"LOW",      fix_type:"DOCUMENT_RULE",     effort:"MEDIUM",impact_score:2.0, title:"6 rules have no comment or description",                                    suggestion:"Add comments to every rule explaining who requested it and what traffic it handles." },
  ],
  optimization: { rules_moved: 2, estimated_speedup: 1.36, policy_equivalent: true,
    model_metrics: { cv_r2_mean: 0.891, cv_r2_std: 0.043,
      feature_importances: { hit_count:0.38, specificity_score:0.19, hit_rate_pct:0.14, bytes_matched:0.11, port_category:0.07, src_prefix_len:0.05, action_int:0.03, protocol_int:0.02, priority_rank_normalized:0.01 }
    }
  }
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
const SEV_COLOR = { CRITICAL:"var(--red)", HIGH:"var(--amber)", MEDIUM:"var(--yellow)", LOW:"var(--green)" };
const SEV_BG    = { CRITICAL:"var(--red-bg)", HIGH:"var(--amb-bg)", MEDIUM:"var(--yel-bg)", LOW:"var(--grn-bg)" };
const TYPE_ICON = { CONTRADICTION:"⚡", SHADOW:"👻", DUPLICATE:"♊", PERMISSIVE:"🔓", REDUNDANT:"🔁" };
const FIX_ICON  = { REVIEW_RULE:"🔍", REMOVE_RULE:"🗑", NARROW_RULE:"🎯", REORDER_RULE:"↕", ADD_DEFAULT_DENY:"🛡", DOCUMENT_RULE:"📝", SPLIT_RULE:"✂" };

function Badge({ sev, small }) {
  return (
    <span style={{
      display:"inline-flex", alignItems:"center", gap:3,
      padding: small ? "1px 6px" : "2px 8px",
      borderRadius:3, fontSize: small ? 10 : 11,
      fontFamily:"var(--mono)", fontWeight:500, letterSpacing:"0.04em",
      color: SEV_COLOR[sev], background: SEV_BG[sev],
      border:`1px solid ${SEV_COLOR[sev]}26`,
    }}>{sev}</span>
  );
}

function Card({ title, children, accent, style }) {
  return (
    <div style={{
      background:"var(--bg1)", border:`1px solid var(--border)`,
      borderRadius:8, overflow:"hidden",
      borderTop: accent ? `2px solid ${accent}` : undefined,
      ...style
    }}>
      {title && (
        <div style={{ padding:"12px 16px", borderBottom:"1px solid var(--border)",
          display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontFamily:"var(--mono)", fontSize:11, fontWeight:500,
            letterSpacing:"0.08em", color:"var(--text-sec)", textTransform:"uppercase" }}>
            {title}
          </span>
        </div>
      )}
      {children}
    </div>
  );
}

// ─── Hit count heatmap ────────────────────────────────────────────────────────
function HeatmapBar({ rule, maxHits }) {
  const pct = maxHits > 0 ? rule.hit_count / maxHits : 0;
  const isAllow = rule.action === "ALLOW";
  const color = pct > 0.6 ? "#60a5fa" : pct > 0.2 ? "#818cf8" : "#334155";

  return (
    <div style={{ display:"flex", alignItems:"center", gap:10, padding:"5px 16px",
      borderBottom:"1px solid var(--border)", cursor:"default",
      transition:"background 0.15s" }}
      onMouseEnter={e => e.currentTarget.style.background = "var(--bg2)"}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
      <div style={{ width:130, flexShrink:0 }}>
        <span style={{ fontFamily:"var(--mono)", fontSize:11, color: isAllow ? "var(--green)" : "var(--red)" }}>
          {isAllow ? "✓" : "✗"}
        </span>
        {" "}
        <span style={{ fontFamily:"var(--mono)", fontSize:11, color:"var(--text-pri)" }}>
          {rule.rule_id.length > 16 ? rule.rule_id.slice(0,15)+"…" : rule.rule_id}
        </span>
      </div>
      <div style={{ flex:1, height:14, background:"var(--bg3)", borderRadius:2, overflow:"hidden" }}>
        <div style={{ width:`${pct * 100}%`, height:"100%", background:color,
          borderRadius:2, transition:"width 1s ease", minWidth: pct > 0 ? 3 : 0 }} />
      </div>
      <div style={{ width:52, textAlign:"right", fontFamily:"var(--mono)", fontSize:11,
        color: pct > 0.2 ? "var(--blue)" : "var(--text-dim)" }}>
        {rule.hit_count.toLocaleString()}
      </div>
    </div>
  );
}

// ─── Conflict graph (SVG) ─────────────────────────────────────────────────────
function ConflictGraph({ findings, rules }) {
  const ruleIds = [...new Set(findings.flatMap(f => [f.rule_a, f.rule_b]))];
  const cols = Math.min(ruleIds.length, 4);
  const rows = Math.ceil(ruleIds.length / cols);
  const W = 580, H = rows * 80 + 60;
  const nodeW = 110, nodeH = 32;
  const xGap = (W - nodeW * cols) / (cols + 1);

  const pos = {};
  ruleIds.forEach((id, i) => {
    const col = i % cols, row = Math.floor(i / cols);
    pos[id] = { x: xGap + col * (nodeW + xGap) + nodeW / 2, y: 40 + row * 80 };
  });

  const linkColor = { CONTRADICTION:"#f05252", SHADOW:"#f59e0b", DUPLICATE:"#818cf8", PERMISSIVE:"#34d399" };

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display:"block" }}>
      <defs>
        {["red","amber","purple","green"].map((c,i) => (
          <marker key={c} id={`arr-${c}`} viewBox="0 0 8 8" refX="6" refY="4"
            markerWidth="6" markerHeight="6" orient="auto">
            <path d="M1 1L7 4L1 7" fill="none"
              stroke={["#f05252","#f59e0b","#818cf8","#34d399"][i]}
              strokeWidth="1.5" strokeLinecap="round" />
          </marker>
        ))}
      </defs>

      {/* Edges */}
      {findings.map((f, i) => {
        const a = pos[f.rule_a], b = pos[f.rule_b];
        if (!a || !b) return null;
        const color = linkColor[f.type] || "#60a5fa";
        const mId = f.type === "CONTRADICTION" ? "arr-red" : f.type === "SHADOW" ? "arr-amber" : "arr-purple";
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - 14;
        return (
          <g key={i}>
            <path d={`M${a.x},${a.y + 16} Q${mx},${my} ${b.x},${b.y + 16}`}
              fill="none" stroke={color} strokeWidth={1.5} strokeDasharray={f.type === "SHADOW" ? "4,3" : "none"}
              opacity={0.6} markerEnd={`url(#${mId})`} />
          </g>
        );
      })}

      {/* Nodes */}
      {ruleIds.map(id => {
        const p = pos[id];
        const rule = rules.find(r => r.rule_id === id);
        const isAllow = rule?.action === "ALLOW";
        const hasCritical = findings.some(f => (f.rule_a === id || f.rule_b === id) && f.severity === "CRITICAL");
        const stroke = hasCritical ? "#f05252" : isAllow ? "#34d399" : "#f59e0b";
        return (
          <g key={id}>
            <rect x={p.x - nodeW/2} y={p.y} width={nodeW} height={nodeH}
              rx={4} fill="var(--bg2)" stroke={stroke} strokeWidth={hasCritical ? 1.5 : 1} />
            <text x={p.x} y={p.y + 13} textAnchor="middle"
              style={{ fontSize:9, fontFamily:"DM Mono, monospace", fill: hasCritical ? "#f05252" : "var(--text-sec)" }}>
              {rule?.action}
            </text>
            <text x={p.x} y={p.y + 24} textAnchor="middle"
              style={{ fontSize:10, fontFamily:"DM Mono, monospace", fill:"var(--text-pri)", fontWeight:500 }}>
              {id.length > 13 ? id.slice(0,12)+"…" : id}
            </text>
          </g>
        );
      })}

      {/* Legend */}
      {[["CONTRADICTION","#f05252"],["SHADOW","#f59e0b"],["DUPLICATE","#818cf8"]].map(([label, color], i) => (
        <g key={label} transform={`translate(${12 + i * 130}, ${H - 18})`}>
          <line x1={0} y1={6} x2={18} y2={6} stroke={color} strokeWidth={1.5}
            strokeDasharray={label === "SHADOW" ? "3,2" : "none"} />
          <text x={22} y={10} style={{ fontSize:9, fontFamily:"DM Mono, monospace", fill:"var(--text-sec)" }}>
            {label}
          </text>
        </g>
      ))}
    </svg>
  );
}

// ─── Feature importance bar chart ────────────────────────────────────────────
function FeatureImportanceChart({ importances }) {
  const sorted = Object.entries(importances).sort((a,b) => b[1]-a[1]).slice(0,7);
  const max = sorted[0][1];
  return (
    <div style={{ padding:"12px 16px", display:"flex", flexDirection:"column", gap:6 }}>
      {sorted.map(([name, score]) => (
        <div key={name} style={{ display:"flex", alignItems:"center", gap:10 }}>
          <div style={{ width:140, flexShrink:0, fontFamily:"var(--mono)", fontSize:10,
            color:"var(--text-sec)", textOverflow:"ellipsis", overflow:"hidden", whiteSpace:"nowrap" }}>
            {name}
          </div>
          <div style={{ flex:1, height:10, background:"var(--bg3)", borderRadius:2, overflow:"hidden" }}>
            <div style={{ width:`${(score/max)*100}%`, height:"100%",
              background:"linear-gradient(90deg, #60a5fa, #818cf8)", borderRadius:2 }} />
          </div>
          <div style={{ width:40, textAlign:"right", fontFamily:"var(--mono)", fontSize:10, color:"var(--blue)" }}>
            {(score*100).toFixed(1)}%
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Rule detail drawer ───────────────────────────────────────────────────────
function RuleDrawer({ rule, onClose }) {
  if (!rule) return null;
  const relatedFindings = SAMPLE_REPORT.findings.filter(f => f.rule_a === rule.rule_id || f.rule_b === rule.rule_id);
  return (
    <div style={{ position:"fixed", top:0, right:0, height:"100vh", width:380,
      background:"var(--bg1)", borderLeft:"1px solid var(--border)",
      zIndex:100, display:"flex", flexDirection:"column",
      boxShadow:"-20px 0 60px rgba(0,0,0,0.5)" }}>
      <div style={{ padding:"16px", borderBottom:"1px solid var(--border)",
        display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <span style={{ fontFamily:"var(--mono)", fontSize:12, color:"var(--text-sec)" }}>
          Rule Detail
        </span>
        <button onClick={onClose} style={{ background:"none", border:"none",
          color:"var(--text-sec)", cursor:"pointer", fontSize:18, lineHeight:1 }}>×</button>
      </div>
      <div style={{ flex:1, overflow:"auto", padding:16, display:"flex", flexDirection:"column", gap:12 }}>
        <div>
          <div style={{ fontFamily:"var(--mono)", fontSize:16, fontWeight:500, color:"var(--text-pri)",
            marginBottom:4 }}>
            {rule.rule_id}
          </div>
          <Badge sev={rule.action === "ALLOW" ? "LOW" : "HIGH"} />
        </div>
        {[
          ["Priority", rule.priority],
          ["Source IP", rule.src_ip],
          ["Destination IP", rule.dst_ip],
          ["Port", rule.dst_port || "any"],
          ["Protocol", rule.protocol],
          ["Action", rule.action],
          ["Comment", rule.comment || "—"],
          ["Hit count", rule.hit_count.toLocaleString()],
        ].map(([k,v]) => (
          <div key={k} style={{ display:"flex", gap:12 }}>
            <span style={{ width:100, flexShrink:0, fontFamily:"var(--mono)", fontSize:11,
              color:"var(--text-dim)" }}>{k}</span>
            <span style={{ fontFamily:"var(--mono)", fontSize:11, color:"var(--text-pri)",
              wordBreak:"break-all" }}>{String(v)}</span>
          </div>
        ))}
        {relatedFindings.length > 0 && (
          <>
            <div style={{ marginTop:8, paddingTop:12, borderTop:"1px solid var(--border)",
              fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)", letterSpacing:"0.08em",
              textTransform:"uppercase" }}>Related findings</div>
            {relatedFindings.map((f,i) => (
              <div key={i} style={{ background:"var(--bg2)", borderRadius:6, padding:"10px 12px",
                border:`1px solid ${SEV_COLOR[f.severity]}26` }}>
                <div style={{ display:"flex", gap:6, marginBottom:4, alignItems:"center" }}>
                  <span style={{ fontSize:12 }}>{TYPE_ICON[f.type]}</span>
                  <span style={{ fontFamily:"var(--mono)", fontSize:10, color:SEV_COLOR[f.severity] }}>{f.type}</span>
                </div>
                <p style={{ fontSize:11, color:"var(--text-sec)", lineHeight:1.5 }}>{f.reason}</p>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

// ─── Main dashboard ───────────────────────────────────────────────────────────
export default function App() {
  const data = SAMPLE_REPORT;
  const [tab, setTab] = useState("overview");
  const [selectedRule, setSelectedRule] = useState(null);
  const [expandedRec, setExpandedRec] = useState(null);
  const [copied, setCopied] = useState(false);
  const maxHits = Math.max(...data.rules.map(r => r.hit_count));

  const sev = { CRITICAL: data.summary.critical_count, HIGH: data.summary.high_count,
    MEDIUM: data.recommendations.filter(r=>r.severity==="MEDIUM").length,
    LOW: data.recommendations.filter(r=>r.severity==="LOW").length };

  const handleExport = (format) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = `firewall_audit.${format === "iptables" ? "iptables" : format}`;
    a.click(); URL.revokeObjectURL(url);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };

  const tabs = [
    { id:"overview",     label:"Overview" },
    { id:"rules",        label:`Rules (${data.rules.length})` },
    { id:"findings",     label:`Findings (${data.findings.length})` },
    { id:"recommendations", label:`Recommendations (${data.recommendations.length})` },
    { id:"ml",           label:"ML Insights" },
  ];

  return (
    <div style={{ minHeight:"100vh", background:"var(--bg0)", fontFamily:"var(--sans)" }}>
      <style>{CSS}</style>

      {/* Header */}
      <div style={{ borderBottom:"1px solid var(--border)", background:"var(--bg1)",
        padding:"0 24px", display:"flex", alignItems:"center", justifyContent:"space-between",
        height:52, position:"sticky", top:0, zIndex:50 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:28, height:28, background:"var(--red-bg)",
            border:"1px solid var(--red)", borderRadius:6,
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>
            🛡
          </div>
          <div>
            <div style={{ fontFamily:"var(--mono)", fontSize:13, fontWeight:500, color:"var(--text-pri)" }}>
              Firewall Rule Optimizer
            </div>
            <div style={{ fontSize:10, color:"var(--text-dim)", fontFamily:"var(--mono)" }}>
              {new Date(data.generated_at).toLocaleString()}
            </div>
          </div>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          {["json","iptables","csv"].map(fmt => (
            <button key={fmt} onClick={() => handleExport(fmt)} style={{
              padding:"5px 12px", borderRadius:5, cursor:"pointer",
              fontFamily:"var(--mono)", fontSize:11, fontWeight:500,
              background:"var(--bg2)", border:"1px solid var(--border)",
              color:"var(--text-sec)", transition:"all 0.15s",
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = "var(--border-h)"; e.currentTarget.style.color = "var(--text-pri)"; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--border)"; e.currentTarget.style.color = "var(--text-sec)"; }}
            >
              ↓ .{fmt}
            </button>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ borderBottom:"1px solid var(--border)", background:"var(--bg1)",
        padding:"0 24px", display:"flex", gap:0 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding:"10px 16px", background:"none", border:"none", cursor:"pointer",
            fontFamily:"var(--mono)", fontSize:11, letterSpacing:"0.04em",
            color: tab === t.id ? "var(--text-pri)" : "var(--text-dim)",
            borderBottom: tab === t.id ? "2px solid var(--blue)" : "2px solid transparent",
            transition:"all 0.15s", marginBottom:-1,
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Body */}
      <div style={{ padding:24, maxWidth:1200, margin:"0 auto" }}>

        {/* ── OVERVIEW ─────────────────────────────────────────────────────── */}
        {tab === "overview" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>

            {/* Stat row */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
              {[
                { label:"Total Rules",    value:data.summary.total_rules, color:"var(--blue)" },
                { label:"Critical",       value:sev.CRITICAL, color:"var(--red)" },
                { label:"High",           value:sev.HIGH, color:"var(--amber)" },
                { label:"Medium",         value:sev.MEDIUM, color:"var(--yellow)" },
                { label:"Recommendations",value:data.summary.total_recommendations, color:"var(--green)" },
              ].map(s => (
                <div key={s.label} style={{ background:"var(--bg1)", border:"1px solid var(--border)",
                  borderRadius:8, padding:"16px", borderTop:`2px solid ${s.color}` }}>
                  <div style={{ fontFamily:"var(--mono)", fontSize:28, fontWeight:300,
                    color:s.color, lineHeight:1 }}>{s.value}</div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
                    marginTop:6, letterSpacing:"0.06em", textTransform:"uppercase" }}>{s.label}</div>
                </div>
              ))}
            </div>

            {/* Middle row: heatmap + conflict graph */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
              <Card title="Rule Hit Count Heatmap" accent="var(--blue)">
                <div style={{ maxHeight:320, overflow:"auto" }}>
                  {[...data.rules].sort((a,b) => b.hit_count - a.hit_count).map(r => (
                    <div key={r.rule_id} onClick={() => setSelectedRule(r)} style={{ cursor:"pointer" }}>
                      <HeatmapBar rule={r} maxHits={maxHits} />
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Conflict Relationship Graph" accent="var(--red)">
                <div style={{ padding:"12px 8px 4px" }}>
                  <ConflictGraph findings={data.findings} rules={data.rules} />
                </div>
              </Card>
            </div>

            {/* Finding type breakdown */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
              {Object.entries(
                data.findings.reduce((acc, f) => { acc[f.type] = (acc[f.type]||0)+1; return acc; }, {})
              ).map(([type, count]) => (
                <div key={type} style={{ background:"var(--bg1)", border:"1px solid var(--border)",
                  borderRadius:8, padding:"14px 16px", display:"flex", gap:12, alignItems:"center" }}>
                  <span style={{ fontSize:22 }}>{TYPE_ICON[type] || "⚠"}</span>
                  <div>
                    <div style={{ fontFamily:"var(--mono)", fontSize:18, fontWeight:300,
                      color: type === "CONTRADICTION" ? "var(--red)" : type === "SHADOW" ? "var(--amber)" : "var(--yellow)" }}>
                      {count}
                    </div>
                    <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
                      textTransform:"uppercase", letterSpacing:"0.06em" }}>{type}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* ML optimization banner */}
            {data.optimization && (
              <div style={{ background:"var(--grn-bg)", border:"1px solid rgba(52,211,153,0.2)",
                borderRadius:8, padding:"14px 20px", display:"flex", gap:32, alignItems:"center" }}>
                <span style={{ fontSize:20 }}>⚡</span>
                <div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:12, color:"var(--green)", fontWeight:500 }}>
                    ML Optimizer Active — {data.optimization.estimated_speedup}x estimated speedup
                  </div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-sec)", marginTop:3 }}>
                    {data.optimization.rules_moved} rules reordered · Policy equivalent: {data.optimization.policy_equivalent ? "✓ Yes" : "✗ No"} · Model R²: {data.optimization.model_metrics.cv_r2_mean.toFixed(3)} ± {data.optimization.model_metrics.cv_r2_std.toFixed(3)}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── RULES ────────────────────────────────────────────────────────── */}
        {tab === "rules" && (
          <Card title="Full Rule Set — click any rule for details">
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead>
                <tr style={{ borderBottom:"1px solid var(--border)" }}>
                  {["Priority","Rule ID","Src IP","Dst IP","Port","Protocol","Action","Hits","Comment"].map(h => (
                    <th key={h} style={{ padding:"8px 12px", textAlign:"left",
                      fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
                      letterSpacing:"0.06em", textTransform:"uppercase", fontWeight:400 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.rules.map((rule, i) => {
                  const isAllow = rule.action === "ALLOW";
                  const isFlagged = data.findings.some(f => f.rule_a === rule.rule_id || f.rule_b === rule.rule_id);
                  return (
                    <tr key={rule.rule_id}
                      onClick={() => setSelectedRule(rule)}
                      style={{ borderBottom:"1px solid var(--border)", cursor:"pointer",
                        background: isFlagged ? "rgba(240,82,82,0.03)" : "transparent",
                        transition:"background 0.12s" }}
                      onMouseEnter={e => e.currentTarget.style.background = "var(--bg2)"}
                      onMouseLeave={e => e.currentTarget.style.background = isFlagged ? "rgba(240,82,82,0.03)" : "transparent"}
                    >
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11, color:"var(--text-dim)" }}>{rule.priority}</td>
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11, color: isFlagged ? "var(--red)" : "var(--text-pri)", fontWeight: isFlagged ? 500 : 400 }}>
                        {isFlagged && "⚠ "}{rule.rule_id}
                      </td>
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11, color:"var(--text-sec)" }}>{rule.src_ip}</td>
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11, color:"var(--text-sec)" }}>{rule.dst_ip}</td>
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11, color:"var(--text-sec)" }}>{rule.dst_port || "any"}</td>
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11, color:"var(--text-sec)" }}>{rule.protocol}</td>
                      <td style={{ padding:"8px 12px" }}>
                        <span style={{ fontFamily:"var(--mono)", fontSize:11, fontWeight:500,
                          color: isAllow ? "var(--green)" : "var(--red)" }}>
                          {isAllow ? "✓ ALLOW" : "✗ DENY"}
                        </span>
                      </td>
                      <td style={{ padding:"8px 12px", fontFamily:"var(--mono)", fontSize:11,
                        color: rule.hit_count > 1000 ? "var(--blue)" : "var(--text-dim)" }}>
                        {rule.hit_count.toLocaleString()}
                      </td>
                      <td style={{ padding:"8px 12px", fontSize:11, color:"var(--text-dim)" }}>{rule.comment || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Card>
        )}

        {/* ── FINDINGS ─────────────────────────────────────────────────────── */}
        {tab === "findings" && (
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            {data.findings.map((f, i) => (
              <div key={i} style={{
                background:"var(--bg1)", borderRadius:8,
                border:`1px solid ${SEV_COLOR[f.severity]}26`,
                borderLeft:`3px solid ${SEV_COLOR[f.severity]}`,
                padding:"14px 16px",
              }}>
                <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:8, flexWrap:"wrap" }}>
                  <span style={{ fontSize:16 }}>{TYPE_ICON[f.type] || "⚠"}</span>
                  <Badge sev={f.severity} />
                  <span style={{ fontFamily:"var(--mono)", fontSize:11, fontWeight:500,
                    color:SEV_COLOR[f.severity] }}>{f.type}</span>
                  <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)" }}>
                    {f.rule_a} → {f.rule_b}
                  </span>
                </div>
                <p style={{ fontSize:12, color:"var(--text-sec)", lineHeight:1.6 }}>{f.reason}</p>
                <div style={{ marginTop:8, display:"flex", gap:8 }}>
                  {[f.rule_a, f.rule_b].filter((v,i,a)=>a.indexOf(v)===i).map(id => (
                    <button key={id} onClick={() => { setSelectedRule(data.rules.find(r=>r.rule_id===id)); setTab("rules"); }}
                      style={{ fontFamily:"var(--mono)", fontSize:10, padding:"2px 8px",
                        background:"var(--bg2)", border:"1px solid var(--border)",
                        borderRadius:3, color:"var(--text-sec)", cursor:"pointer" }}>
                      View {id}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── RECOMMENDATIONS ──────────────────────────────────────────────── */}
        {tab === "recommendations" && (
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {data.recommendations.map((rec) => (
              <div key={rec.rec_id} style={{
                background:"var(--bg1)", borderRadius:8,
                border:`1px solid ${SEV_COLOR[rec.severity]}26`,
                overflow:"hidden",
              }}>
                <div onClick={() => setExpandedRec(expandedRec === rec.rec_id ? null : rec.rec_id)}
                  style={{ padding:"12px 16px", cursor:"pointer", display:"flex",
                    gap:12, alignItems:"center", justifyContent:"space-between",
                    background: expandedRec === rec.rec_id ? "var(--bg2)" : "transparent" }}
                  onMouseEnter={e => e.currentTarget.style.background = "var(--bg2)"}
                  onMouseLeave={e => { if (expandedRec !== rec.rec_id) e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ display:"flex", gap:10, alignItems:"center", flex:1, minWidth:0 }}>
                    <span style={{ fontSize:16, flexShrink:0 }}>{FIX_ICON[rec.fix_type] || "🔧"}</span>
                    <div style={{ minWidth:0 }}>
                      <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:2, flexWrap:"wrap" }}>
                        <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)" }}>{rec.rec_id}</span>
                        <Badge sev={rec.severity} small />
                        <span style={{ fontFamily:"var(--mono)", fontSize:10,
                          color:"var(--text-dim)" }}>{rec.fix_type.replace(/_/g," ")}</span>
                        <span style={{ fontFamily:"var(--mono)", fontSize:10,
                          padding:"1px 6px", borderRadius:3,
                          background:"var(--bg3)", color:"var(--text-dim)" }}>
                          effort: {rec.effort}
                        </span>
                      </div>
                      <div style={{ fontSize:12, color:"var(--text-pri)", fontWeight:500,
                        overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {rec.title}
                      </div>
                    </div>
                  </div>
                  <div style={{ display:"flex", alignItems:"center", gap:10, flexShrink:0 }}>
                    <div style={{ textAlign:"right" }}>
                      <div style={{ fontFamily:"var(--mono)", fontSize:14, fontWeight:300,
                        color:SEV_COLOR[rec.severity] }}>{rec.impact_score.toFixed(1)}</div>
                      <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)" }}>impact</div>
                    </div>
                    <span style={{ color:"var(--text-dim)", fontSize:12 }}>
                      {expandedRec === rec.rec_id ? "▲" : "▼"}
                    </span>
                  </div>
                </div>

                {expandedRec === rec.rec_id && (
                  <div style={{ padding:"14px 16px", borderTop:"1px solid var(--border)",
                    display:"flex", flexDirection:"column", gap:10 }}>
                    <div>
                      <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
                        textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:6 }}>Suggestion</div>
                      <p style={{ fontSize:12, color:"var(--text-sec)", lineHeight:1.6,
                        background:"var(--bg2)", padding:"10px 12px", borderRadius:6,
                        borderLeft:`2px solid ${SEV_COLOR[rec.severity]}` }}>
                        {rec.suggestion}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── ML INSIGHTS ──────────────────────────────────────────────────── */}
        {tab === "ml" && data.optimization && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
              {[
                { label:"Estimated Speedup",    value:`${data.optimization.estimated_speedup}x`, color:"var(--green)" },
                { label:"Model R² (CV)",         value:data.optimization.model_metrics.cv_r2_mean.toFixed(3), color:"var(--blue)" },
                { label:"Rules Reordered",       value:data.optimization.rules_moved, color:"var(--amber)" },
              ].map(s => (
                <div key={s.label} style={{ background:"var(--bg1)", border:"1px solid var(--border)",
                  borderRadius:8, padding:"20px", textAlign:"center" }}>
                  <div style={{ fontFamily:"var(--mono)", fontSize:32, fontWeight:300, color:s.color }}>{s.value}</div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
                    marginTop:8, textTransform:"uppercase", letterSpacing:"0.06em" }}>{s.label}</div>
                </div>
              ))}
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
              <Card title="Feature Importances (GBT Model)" accent="var(--blue)">
                <FeatureImportanceChart importances={data.optimization.model_metrics.feature_importances} />
              </Card>

              <Card title="Traffic-based Rule Ranking" accent="var(--green)">
                <div style={{ padding:"12px 16px", display:"flex", flexDirection:"column", gap:6 }}>
                  {[...data.rules].sort((a,b) => b.hit_count - a.hit_count).map((r, i) => (
                    <div key={r.rule_id} style={{ display:"flex", gap:10, alignItems:"center" }}>
                      <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
                        width:20, textAlign:"right", flexShrink:0 }}>#{i+1}</span>
                      <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-pri)",
                        width:130, flexShrink:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {r.rule_id}
                      </span>
                      <div style={{ flex:1, height:8, background:"var(--bg3)", borderRadius:2, overflow:"hidden" }}>
                        <div style={{ width:`${(r.hit_count/maxHits)*100}%`, height:"100%",
                          background:"var(--green)", borderRadius:2, opacity:0.7 }} />
                      </div>
                      <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--green)",
                        width:44, textAlign:"right", flexShrink:0 }}>{r.hit_count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </Card>
            </div>

            <Card title="Model Configuration">
              <div style={{ padding:"14px 16px", display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
                {[
                  ["Algorithm", "GradientBoostingRegressor"],
                  ["Estimators", "100"],
                  ["Max Depth", "4"],
                  ["Learning Rate", "0.1"],
                  ["Subsample", "0.8"],
                  ["CV Folds", "5"],
                ].map(([k,v]) => (
                  <div key={k} style={{ background:"var(--bg2)", borderRadius:6, padding:"10px 12px" }}>
                    <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
                      textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:4 }}>{k}</div>
                    <div style={{ fontFamily:"var(--mono)", fontSize:12, color:"var(--text-pri)" }}>{v}</div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}
      </div>

      {/* Rule drawer */}
      {selectedRule && <RuleDrawer rule={selectedRule} onClose={() => setSelectedRule(null)} />}
    </div>
  );
}