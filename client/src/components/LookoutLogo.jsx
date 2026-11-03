export function LookoutLogo({ className = "w-5 h-5" }) {
  return (
    <div className="relative flex items-center justify-center shrink-0 transition-transform duration-200 ease-out group-hover:scale-105">
      {/* Subtle ambient brand glow behind the mark */}
      <div className="absolute inset-0 bg-indigo-500/20 group-hover:bg-indigo-500/30 blur-md rounded-full pointer-events-none transition-colors duration-200" />

      <svg
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className={`${className} relative z-10 text-zinc-900 dark:text-white`}
      >
        {/* Outer Geometric Shield Frame */}
        <path
          d="M12 2.5L20 6.5V11.5C20 16.5 16.5 20.8 12 22C7.5 20.8 4 16.5 4 11.5V6.5L12 2.5Z"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="stroke-zinc-900 dark:stroke-zinc-100"
        />
        {/* Inner Sentinel Focal Aperture / Radar Reticle */}
        <circle
          cx="12"
          cy="11.5"
          r="3"
          stroke="currentColor"
          strokeWidth="1.4"
          className="stroke-indigo-500 dark:stroke-indigo-400"
        />
        {/* Center Target Dot */}
        <circle
          cx="12"
          cy="11.5"
          r="1"
          fill="currentColor"
          className="fill-indigo-500 dark:fill-indigo-400"
        />
      </svg>
    </div>
  );
}

export default LookoutLogo;
