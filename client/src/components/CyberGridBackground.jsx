import { useEffect, useRef } from "react";

export default function CyberGridBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const mouse = { x: -1000, y: -1000, active: false };

    const handleMouseMove = (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    };

    const handleMouseLeave = () => {
      mouse.active = false;
    };

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
      initDataStreams();
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseleave", handleMouseLeave);
    window.addEventListener("resize", handleResize);

    const GRID_SIZE = 52;

    // Vector data streams
    let streams = [];
    const STREAM_COUNT = 24;

    const createStream = () => {
      const isHorizontal = Math.random() > 0.45;
      const speed = (0.35 + Math.random() * 0.55) * (Math.random() > 0.5 ? 1 : -1);
      const length = 50 + Math.random() * 90;
      const colorType = Math.random() > 0.8 ? "emerald" : "cyan"; // subtle cyber accent

      if (isHorizontal) {
        const gridY = Math.floor(Math.random() * (height / GRID_SIZE)) * GRID_SIZE;
        const x = speed > 0 ? -length - Math.random() * 200 : width + length + Math.random() * 200;
        return { isHorizontal: true, x, y: gridY, speed, length, colorType, alpha: 0.18 + Math.random() * 0.15 };
      } else {
        const gridX = Math.floor(Math.random() * (width / GRID_SIZE)) * GRID_SIZE;
        const y = speed > 0 ? -length - Math.random() * 200 : height + length + Math.random() * 200;
        return { isHorizontal: false, x: gridX, y, speed, length, colorType, alpha: 0.18 + Math.random() * 0.15 };
      }
    };

    const initDataStreams = () => {
      streams = [];
      for (let i = 0; i < STREAM_COUNT; i++) {
        const stream = createStream();
        // pre-advance positions across canvas
        if (stream.isHorizontal) {
          stream.x = Math.random() * width;
        } else {
          stream.y = Math.random() * height;
        }
        streams.push(stream);
      }
    };

    initDataStreams();

    let lastTime = performance.now();

    const render = (currentTime) => {
      const dt = Math.min((currentTime - lastTime) / 1000, 0.1);
      lastTime = currentTime;

      // Base background
      ctx.fillStyle = "#090A0E";
      ctx.fillRect(0, 0, width, height);

      // Subtle ambient radial glow in the center / top
      const radialGlow = ctx.createRadialGradient(
        width * 0.5,
        height * 0.25,
        50,
        width * 0.5,
        height * 0.5,
        Math.max(width, height) * 0.8
      );
      radialGlow.addColorStop(0, "rgba(56, 189, 248, 0.035)");
      radialGlow.addColorStop(0.5, "rgba(15, 23, 42, 0.01)");
      radialGlow.addColorStop(1, "rgba(9, 10, 14, 0)");
      ctx.fillStyle = radialGlow;
      ctx.fillRect(0, 0, width, height);

      // Draw cyber grid lines
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(39, 39, 42, 0.4)"; // subtle #27272A grid

      // Vertical lines
      const startX = 0;
      for (let x = startX; x <= width; x += GRID_SIZE) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }

      // Horizontal lines
      for (let y = 0; y <= height; y += GRID_SIZE) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Draw faint crosshair / dot markers at intersections
      const crossSize = 2;
      for (let x = 0; x <= width; x += GRID_SIZE) {
        for (let y = 0; y <= height; y += GRID_SIZE) {
          let distToMouse = 9999;
          if (mouse.active) {
            const dx = x - mouse.x;
            const dy = y - mouse.y;
            distToMouse = Math.sqrt(dx * dx + dy * dy);
          }

          if (distToMouse < 180) {
            // Interactive mouse glow near cursor
            const factor = 1 - distToMouse / 180;
            ctx.fillStyle = `rgba(56, 189, 248, ${0.1 + factor * 0.35})`;
            ctx.beginPath();
            ctx.arc(x, y, 1.5, 0, Math.PI * 2);
            ctx.fill();

            // faint micro crosshair
            ctx.strokeStyle = `rgba(56, 189, 248, ${factor * 0.25})`;
            ctx.beginPath();
            ctx.moveTo(x - 4, y);
            ctx.lineTo(x + 4, y);
            ctx.moveTo(x, y - 4);
            ctx.lineTo(x, y + 4);
            ctx.stroke();
          } else if ((x + y) % (GRID_SIZE * 3) === 0) {
            // Subtle ambient crosshair nodes
            ctx.fillStyle = "rgba(56, 189, 248, 0.08)";
            ctx.fillRect(x - 0.75, y - 0.75, 1.5, 1.5);
          }
        }
      }

      // Update & render data-stream vectors
      for (let i = 0; i < streams.length; i++) {
        const s = streams[i];

        if (s.isHorizontal) {
          s.x += s.speed * (dt * 60);
          if (s.speed > 0 && s.x - s.length > width) {
            streams[i] = createStream();
            streams[i].x = -streams[i].length;
          } else if (s.speed < 0 && s.x + s.length < 0) {
            streams[i] = createStream();
            streams[i].x = width + streams[i].length;
          }

          const grad = ctx.createLinearGradient(
            s.speed > 0 ? s.x - s.length : s.x + s.length,
            s.y,
            s.x,
            s.y
          );
          const color = s.colorType === "emerald" ? "16, 185, 129" : "56, 189, 248";
          grad.addColorStop(0, `rgba(${color}, 0)`);
          grad.addColorStop(0.85, `rgba(${color}, ${s.alpha})`);
          grad.addColorStop(1, `rgba(${color}, ${s.alpha * 1.5})`);

          ctx.strokeStyle = grad;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(s.speed > 0 ? s.x - s.length : s.x + s.length, s.y);
          ctx.lineTo(s.x, s.y);
          ctx.stroke();

          // glowing head dot
          ctx.fillStyle = `rgba(${color}, ${Math.min(s.alpha * 2, 0.8)})`;
          ctx.beginPath();
          ctx.arc(s.x, s.y, 1.25, 0, Math.PI * 2);
          ctx.fill();
        } else {
          s.y += s.speed * (dt * 60);
          if (s.speed > 0 && s.y - s.length > height) {
            streams[i] = createStream();
            streams[i].y = -streams[i].length;
          } else if (s.speed < 0 && s.y + s.length < 0) {
            streams[i] = createStream();
            streams[i].y = height + streams[i].length;
          }

          const grad = ctx.createLinearGradient(
            s.x,
            s.speed > 0 ? s.y - s.length : s.y + s.length,
            s.x,
            s.y
          );
          const color = s.colorType === "emerald" ? "16, 185, 129" : "56, 189, 248";
          grad.addColorStop(0, `rgba(${color}, 0)`);
          grad.addColorStop(0.85, `rgba(${color}, ${s.alpha})`);
          grad.addColorStop(1, `rgba(${color}, ${s.alpha * 1.5})`);

          ctx.strokeStyle = grad;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(s.x, s.speed > 0 ? s.y - s.length : s.y + s.length);
          ctx.lineTo(s.x, s.y);
          ctx.stroke();

          // glowing head dot
          ctx.fillStyle = `rgba(${color}, ${Math.min(s.alpha * 2, 0.8)})`;
          ctx.beginPath();
          ctx.arc(s.x, s.y, 1.25, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // Vignette effect to fade edges into #090A0E
      const vignette = ctx.createRadialGradient(
        width / 2,
        height / 2,
        Math.min(width, height) * 0.4,
        width / 2,
        height / 2,
        Math.max(width, height) * 0.75
      );
      vignette.addColorStop(0, "rgba(9, 10, 14, 0)");
      vignette.addColorStop(0.7, "rgba(9, 10, 14, 0.4)");
      vignette.addColorStop(1, "rgba(9, 10, 14, 0.92)");
      ctx.fillStyle = vignette;
      ctx.fillRect(0, 0, width, height);

      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseleave", handleMouseLeave);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 w-full h-full pointer-events-none z-0"
      style={{ background: "#090A0E" }}
    />
  );
}
