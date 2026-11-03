import React from "react";
import {
  TopoField,
  DefenseLines,
  InterfaceLines,
  ConnectivityGraph,
  GatewayFlow,
  ParticleNetwork,
  ParticleDrift,
  ConstellationField as BaseConstellationField,
  type NeuformBatchEffectProps,
} from "./neuform-isolated/NeuformBatchEffects";

const VARIANT_MAP: Record<string, React.ComponentType<NeuformBatchEffectProps>> = {
  "constellation-field": BaseConstellationField,
  "particle-drift": ParticleDrift,
  "particle-network": ParticleNetwork,
  "gateway-flow": GatewayFlow,
  "connectivity-graph": ConnectivityGraph,
  "interface-lines": InterfaceLines,
  "defense-lines": DefenseLines,
  "topo-field": TopoField,
};

export type ConstellationFieldVariant =
  | "constellation-field"
  | "particle-drift"
  | "particle-network"
  | "gateway-flow"
  | "connectivity-graph"
  | "interface-lines"
  | "defense-lines"
  | "topo-field";

export type ConstellationFieldProps = NeuformBatchEffectProps & {
  variant?: ConstellationFieldVariant | string;
};

export function ConstellationField({ variant = "constellation-field", ...props }: ConstellationFieldProps) {
  const Component = VARIANT_MAP[variant] || BaseConstellationField;
  return React.createElement(Component, props);
}

export * from "./neuform-isolated/NeuformBatchEffects";
