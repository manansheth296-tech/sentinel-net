export const mockResult = {
  infiltration_timeline: [
    { window_start: "10:00:00", probability: 0.12 },
    { window_start: "10:00:10", probability: 0.34 },
    { window_start: "10:00:20", probability: 0.63 },
    { window_start: "10:00:30", probability: 0.88 },
    { window_start: "10:00:40", probability: 0.91 },
  ],
  predicted_stage: "Lateral Movement",
  stage_probs: {
    Reconnaissance: 0.05,
    "Initial Access": 0.10,
    "Lateral Movement": 0.55,
    "Command & Control": 0.20,
    Impact: 0.10,
  },
  top_features: [
    { feature: "SYN Flag Count", importance: 0.31 },
    { feature: "Fwd IAT Mean", importance: 0.22 },
    { feature: "Flow Duration", importance: 0.15 },
    { feature: "Flow Byts/s", importance: 0.11 },
    { feature: "PSH Flag Count", importance: 0.08 },
  ],
  flagged_flows: [
    { src_ip: "172.31.69.25", dst_ip: "18.218.115.60", risk_score: 0.91 },
    { src_ip: "172.31.69.28", dst_ip: "18.219.9.1", risk_score: 0.76 },
    { src_ip: "10.0.0.14", dst_ip: "52.14.67.200", risk_score: 0.54 },
  ],
  benchmark: {
    world_model: { f1: 0.8403, precision: 0.9304, recall: 0.7662, fpr: 0.0167 },
    logistic_baseline: { f1: 0.6120, precision: 0.6840, recall: 0.5540, fpr: 0.0820 },
  },
};
