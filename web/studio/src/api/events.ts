import type { StudioEvent } from "../types";

export function subscribeToRun(runId: string, onEvent: (event: StudioEvent) => void): EventSource {
  const source = new EventSource(`/api/events/stream?run_id=${encodeURIComponent(runId)}`);
  source.addEventListener("studio_event", (message) => {
    onEvent(JSON.parse((message as MessageEvent).data) as StudioEvent);
  });
  return source;
}

export function subscribeToAllEvents(onEvent: (event: StudioEvent) => void): EventSource {
  const source = new EventSource("/api/events/stream");
  source.addEventListener("studio_event", (message) => {
    onEvent(JSON.parse((message as MessageEvent).data) as StudioEvent);
  });
  return source;
}
