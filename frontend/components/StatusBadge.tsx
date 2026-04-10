// shared status badge with pulse animation for active states

const ACTIVE_STATES = ["pending", "detonating", "extracting", "queued", "generating"];

export default function StatusBadge({ status }: { status: string }) {
  const isActive = ACTIVE_STATES.includes(status);

  return (
    <span className={`badge badge-${status} ${isActive ? "pulse-active" : ""}`}>
      {status}
      {isActive && <span className="dot" />}
    </span>
  );
}
