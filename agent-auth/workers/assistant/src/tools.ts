/**
 * The tools the LLM may call. Each one maps to exactly one agent endpoint and
 * the *minimum* scopes that endpoint needs.
 *
 * The LLM is treated as untrusted: it only picks a tool name and arguments,
 * which we validate here. Whether the call is *allowed* is decided by the
 * authorization server's policy, not by the model.
 */
import { z } from "zod";

export interface ToolSpec {
  description: string;
  parameters: Record<string, { type: "string"; description: string }>;
  required: string[];
  audience: string;
  method: "GET" | "POST";
  path: string;
  scopes: string[];
  /** Turn the model's raw arguments into a request body (throws on bad input). */
  toBody?: (args: Record<string, unknown>) => unknown;
}

const emails = z
  .string()
  .transform((s) => s.split(",").map((e) => e.trim()).filter(Boolean))
  .pipe(z.array(z.string().email()));

const EmailArgs = z.object({ to: emails, subject: z.string().min(1), body: z.string() });

export const TOOLS: Record<string, ToolSpec> = {
  list_events: {
    description: "List the user's calendar events.",
    parameters: {},
    required: [],
    audience: "calendar-agent",
    method: "GET",
    path: "/events",
    scopes: ["calendar:read"],
  },
  create_event: {
    description: "Add an event to the user's calendar.",
    parameters: {
      title: { type: "string", description: "Short title of the event" },
      start: { type: "string", description: "Start time, ISO 8601, e.g. 2026-10-10T09:00" },
      attendees: { type: "string", description: "Comma-separated attendee email addresses (may be empty)" },
    },
    required: ["title", "start"],
    audience: "calendar-agent",
    method: "POST",
    path: "/events",
    scopes: ["calendar:write"],
    toBody: (args) =>
      z.object({ title: z.string().min(1), start: z.string().min(1), attendees: emails.default([]) }).parse(args),
  },
  draft_email: {
    description: "Save an email draft for the user to review and send later.",
    parameters: {
      to: { type: "string", description: "Comma-separated recipient email addresses" },
      subject: { type: "string", description: "Subject line" },
      body: { type: "string", description: "Plain-text body" },
    },
    required: ["to", "subject", "body"],
    audience: "email-agent",
    method: "POST",
    path: "/drafts",
    scopes: ["email:draft"],
    toBody: (args) => EmailArgs.parse(args),
  },
  // Deliberately offered to the model: policy does NOT grant email:send, so
  // the auth server will refuse it. This shows least privilege containing a
  // model that has been talked into doing something it shouldn't.
  send_email: {
    description: "Send an email immediately.",
    parameters: {
      to: { type: "string", description: "Comma-separated recipient email addresses" },
      subject: { type: "string", description: "Subject line" },
      body: { type: "string", description: "Plain-text body" },
    },
    required: ["to", "subject", "body"],
    audience: "email-agent",
    method: "POST",
    path: "/send",
    scopes: ["email:send"],
    toBody: (args) => EmailArgs.parse(args),
  },
};

/** Tool definitions in the shape Workers AI function-calling models expect. */
export function toolDefinitions() {
  return Object.entries(TOOLS).map(([name, t]) => ({
    type: "function",
    function: {
      name,
      description: t.description,
      parameters: { type: "object", properties: t.parameters, required: t.required },
    },
  }));
}
