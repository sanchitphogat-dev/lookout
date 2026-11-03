import { useEffect, useRef } from "react";
import * as THREE from "three";

const NOISE_GLSL = `
  vec4 permute(vec4 x){ return mod(((x*34.0)+1.0)*x, 289.0); }
  vec4 taylorInvSqrt(vec4 r){ return 1.79284291400159 - 0.85373472095314 * r; }

  float snoise(vec3 v){
    const vec2  C = vec2(1.0/6.0, 1.0/3.0);
    const vec4  D = vec4(0.0, 0.5, 1.0, 2.0);

    vec3 i  = floor(v + dot(v, C.yyy));
    vec3 x0 = v - i + dot(i, C.xxx);

    vec3 g = step(x0.yzx, x0.xyz);
    vec3 l = 1.0 - g;
    vec3 i1 = min(g.xyz, l.zxy);
    vec3 i2 = max(g.xyz, l.zxy);

    vec3 x1 = x0 - i1 + C.xxx;
    vec3 x2 = x0 - i2 + C.yyy;
    vec3 x3 = x0 - D.yyy;

    i = mod(i, 289.0);
    vec4 p = permute( permute( permute(
              i.z + vec4(0.0, i1.z, i2.z, 1.0 ))
            + i.y + vec4(0.0, i1.y, i2.y, 1.0 ))
            + i.x + vec4(0.0, i1.x, i2.x, 1.0 ));

    float n_ = 0.142857142857;
    vec3  ns = n_ * D.wyz - D.xzx;

    vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
    vec4 x_ = floor(j * ns.z);
    vec4 y_ = floor(j - 7.0 * x_ );

    vec4 x = x_ *ns.x + ns.yyyy;
    vec4 y = y_ *ns.x + ns.yyyy;
    vec4 h = 1.0 - abs(x) - abs(y);

    vec4 b0 = vec4( x.xy, y.xy );
    vec4 b1 = vec4( x.zw, y.zw );

    vec4 s0 = floor(b0)*2.0 + 1.0;
    vec4 s1 = floor(b1)*2.0 + 1.0;
    vec4 sh = -step(h, vec4(0.0));

    vec4 a0 = b0.xzyw + s0.xzyw*sh.xxyy ;
    vec4 a1 = b1.xzyw + s1.xzyw*sh.zzww ;

    vec3 p0 = vec3(a0.xy,h.x);
    vec3 p1 = vec3(a0.zw,h.y);
    vec3 p2 = vec3(a1.xy,h.z);
    vec3 p3 = vec3(a1.zw,h.w);

    vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
    p0 *= norm.x;
    p1 *= norm.y;
    p2 *= norm.z;
    p3 *= norm.w;

    vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
    m = m * m;
    return 42.0 * dot( m*m, vec4( dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3) ) );
  }
`;

class CpuNoise {
  constructor(seed = Math.random() * 13758) {
    this.seed = seed;
  }
  hash(n) {
    const x = Math.sin(this.seed * 12.9898 + n * 78.233) * 43758.5453123;
    return x - Math.floor(x);
  }
  getVal(t) {
    const xi = Math.floor(t);
    const xf = t - xi;
    const u = xf * xf * (3.0 - 2.0 * xf);
    return this.hash(xi) * (1.0 - u) + this.hash(xi + 1) * u;
  }
}

const lerp = (a, b, t, minOut, maxOut) => ((a - b) * (maxOut - minOut)) / (t - b) + minOut;

function poissonDiscSampler({ minDistance, maxDistance, shape, tries = 20 }) {
  const [width, height] = shape;
  const cell = minDistance / Math.SQRT2;
  const gridWidth = Math.ceil(width / cell);
  const gridHeight = Math.ceil(height / cell);
  const grid = new Array(gridWidth * gridHeight);
  const points = [];
  const active = [];

  const randRange = (min, max) => min + Math.random() * (max - min);
  const randomPoint = () => [randRange(minDistance, width - minDistance), randRange(minDistance, height - minDistance)];

  const gridIndex = (x, y) => (Math.floor(x / cell) % gridWidth) + Math.floor(y / cell) * gridWidth;

  const inShape = (p) =>
    p[0] >= minDistance && p[0] <= width - minDistance &&
    p[1] >= minDistance && p[1] <= height - minDistance;

  const fits = (p) => {
    const xg = Math.floor(p[0] / cell);
    const yg = Math.floor(p[1] / cell);
    const range = Math.ceil(maxDistance / cell);
    for (let dy = -range; dy <= range; dy++) {
      for (let dx = -range; dx <= range; dx++) {
        const nx = xg + dx;
        const ny = yg + dy;
        if (nx < 0 || ny < 0 || nx >= gridWidth || ny >= gridHeight) continue;
        const cellPoint = grid[ny * gridWidth + nx];
        if (!cellPoint) continue;
        const dSq = (cellPoint[0] - p[0]) ** 2 + (cellPoint[1] - p[1]) ** 2;
        if (dSq < minDistance * minDistance) return false;
      }
    }
    return true;
  };

  const first = randomPoint();
  first[0] = width / 2;
  first[1] = height / 2;
  grid[gridIndex(first[0], first[1])] = first;
  points.push(first);
  active.push(first);

  while (active.length > 0) {
    const idx = Math.floor(Math.random() * active.length);
    const ref = active[idx];
    let placed = false;
    for (let i = 0; i < tries; i++) {
      const angle = randRange(0, Math.PI * 2);
      const radius = randRange(minDistance, maxDistance);
      const candidate = [ref[0] + Math.cos(angle) * radius, ref[1] + Math.sin(angle) * radius];
      if (inShape(candidate) && fits(candidate)) {
        grid[gridIndex(candidate[0], candidate[1])] = candidate;
        points.push(candidate);
        active.push(candidate);
        placed = true;
        break;
      }
    }
    if (!placed) active.splice(idx, 1);
  }

  return { fill: () => points };
}

class AntigravityParticles {
  constructor(scene) {
    this.scene = scene;
    this.renderer = scene.renderer;
    this.camera = scene.camera;
    this.lastTime = 0;
    this.everRendered = false;
    this.ringPos = new THREE.Vector2(0, 0);
    this.cursorPos = new THREE.Vector2(0, 0);
    this.colorScheme = scene.theme === "dark" ? 0 : 1;
    this.particleScale =
      scene.renderer.domElement.width / scene.pixelRatio / 2000 * scene.particlesScale;
    this.createPoints();
    this.init();
  }

  createPoints() {
    const poisson = poissonDiscSampler({
      shape: [500, 500],
      minDistance: lerp(this.scene.density, 0, 300, 10, 2),
      maxDistance: lerp(this.scene.density, 0, 300, 11, 3),
      tries: 20,
    });
    const points = poisson.fill();
    this.pointsData = [];
    for (let t = 0; t < points.length; t++) {
      this.pointsData.push(points[t][0] - 250, points[t][1] - 250);
    }
    this.count = this.pointsData.length / 2;
  }

  createDataTexturePosition() {
    const data = new Float32Array(this.length * 4);
    for (let t = 0; t < this.count; t++) {
      const n = t * 4;
      data[n + 0] = this.pointsData[t * 2 + 0] * (1 / 250);
      data[n + 1] = this.pointsData[t * 2 + 1] * (1 / 250);
      data[n + 2] = 0;
      data[n + 3] = 0;
    }
    const tex = new THREE.DataTexture(
      data,
      this.size,
      this.size,
      THREE.RGBAFormat,
      THREE.FloatType
    );
    tex.needsUpdate = true;
    return tex;
  }

  createRenderTarget() {
    return new THREE.WebGLRenderTarget(this.size, this.size, {
      wrapS: THREE.ClampToEdgeWrapping,
      wrapT: THREE.ClampToEdgeWrapping,
      minFilter: THREE.NearestFilter,
      magFilter: THREE.NearestFilter,
      format: THREE.RGBAFormat,
      type: THREE.FloatType,
      depthBuffer: false,
      stencilBuffer: false,
    });
  }

  init() {
    this.size = 256;
    this.length = this.size * this.size;
    this.posTex = this.createDataTexturePosition();
    this.rt1 = this.createRenderTarget();
    this.rt2 = this.createRenderTarget();
    this.renderer.setRenderTarget(this.rt1);
    this.renderer.setClearColor(0, 0);
    this.renderer.clear();
    this.renderer.setRenderTarget(this.rt2);
    this.renderer.setClearColor(0, 0);
    this.renderer.clear();
    this.renderer.setRenderTarget(null);

    this.noise = new CpuNoise();
    this.simScene = new THREE.Scene();
    this.simCamera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);

    this.simMaterial = new THREE.ShaderMaterial({
      uniforms: {
        uPosition: { value: this.posTex },
        uPosRefs: { value: this.posTex },
        uRingPos: { value: new THREE.Vector2(0, 0) },
        uRingRadius: { value: 0.2 },
        uDeltaTime: { value: 0 },
        uRingWidth: { value: 0.05 },
        uRingWidth2: { value: 0.015 },
        uRingDisplacement: { value: this.scene.ringDisplacement },
        uTime: { value: 0 },
      },
      vertexShader: `
        void main() {
          gl_Position = vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        precision highp float;
        uniform sampler2D uPosition;
        uniform sampler2D uPosRefs;
        uniform vec2 uRingPos;
        uniform float uTime;
        uniform float uDeltaTime;
        uniform float uRingRadius;

        uniform float uRingWidth;
        uniform float uRingWidth2;
        uniform float uRingDisplacement;

        ${NOISE_GLSL}

        void main() {

            vec2 simTexCoords = gl_FragCoord.xy / vec2(${this.size.toFixed(1)}, ${this.size.toFixed(1)});
            vec4 pFrame = texture2D(uPosition, simTexCoords);

            float scale = pFrame.z;
            float velocity = pFrame.w;
            vec2 refPos = texture2D(uPosRefs, simTexCoords).xy;

            float time = uTime * .5;
            vec2 curentPos = refPos;

            vec2 pos = pFrame.xy;
            pos *= .8;

            float dist = distance(curentPos.xy, uRingPos);
            float noise0 = snoise(vec3(curentPos.xy * .2 + vec2(18.4924, 72.9744), time * 0.5));
            float dist1 = distance(curentPos.xy + (noise0 * .005), uRingPos);


            float t = smoothstep(uRingRadius - (uRingWidth * 2.), uRingRadius, dist) - smoothstep(uRingRadius, uRingRadius + uRingWidth, dist1);
            float t2 = smoothstep(uRingRadius - (uRingWidth2 * 2.), uRingRadius, dist) - smoothstep(uRingRadius, uRingRadius + uRingWidth2, dist1);
            float t3 = smoothstep(uRingRadius + uRingWidth2, uRingRadius, dist);

            t = pow(t, 2.);
            t2 = pow(t2, 3.);

            t += t2 * 3.;
            t += t3 * .4;
            t += snoise(vec3(curentPos.xy * 30. + vec2(11.4924, 12.9744), time * 0.5)) * t3 * .5;

            float nS = snoise(vec3(curentPos.xy * 2. + vec2(18.4924, 72.9744), time * 0.5));
            t += pow((nS + 1.5) * .5, 2.) * .6;

            float noise1 = snoise(vec3(curentPos.xy * 4. + vec2(88.494, 32.4397), time * 0.35));
            float noise2 = snoise(vec3(curentPos.xy * 4. + vec2(50.904, 120.947), time * 0.35));

            float noise3 = snoise(vec3(curentPos.xy * 20. + vec2(18.4924, 72.9744), time * .5));
            float noise4 = snoise(vec3(curentPos.xy * 20. + vec2(50.904, 120.947), time * .5));

            vec2 disp = vec2(noise1, noise2) * .03;
            disp += vec2(noise3, noise4) * .005;

            disp.x += sin((refPos.x * 20.) + (time * 4.)) * .02 * clamp(dist, 0., 1.);
            disp.y += cos((refPos.y * 20.) + (time * 3.)) * .02 * clamp(dist, 0., 1.);

            pos -= (uRingPos - (curentPos + disp)) * pow(t2, .75) * uRingDisplacement;

            float scaleDiff = t - scale;
            scaleDiff *= .2;
            scale += scaleDiff;

            vec2 finalPos = curentPos + disp + (pos * .25);

            velocity *= .5;
            velocity += scale * .25;

            vec4 frame = vec4(finalPos, scale, velocity);

            gl_FragColor = frame;

        }
      `,
    });

    const simMesh = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), this.simMaterial);
    this.simScene.add(simMesh);

    const geometry = new THREE.BufferGeometry();
    const uv = new Float32Array(this.count * 2);
    const position = new Float32Array(this.count * 3);
    const seeds = new Float32Array(this.count * 4);

    for (let e = 0; e < this.count; e++) {
      const t = e % this.size;
      const n = Math.floor(e / this.size);
      uv[e * 2] = t / this.size;
      uv[e * 2 + 1] = n / this.size;
    }

    for (let e = 0; e < this.count; e++) {
      seeds[e * 4] = Math.random();
      seeds[e * 4 + 1] = Math.random();
      seeds[e * 4 + 2] = Math.random();
      seeds[e * 4 + 3] = Math.random();
    }

    geometry.setAttribute("position", new THREE.BufferAttribute(position, 3));
    geometry.setAttribute("uv", new THREE.BufferAttribute(uv, 2));
    geometry.setAttribute("seeds", new THREE.BufferAttribute(seeds, 4));

    this.renderMaterial = new THREE.ShaderMaterial({
      uniforms: {
        uPosition: { value: this.posTex },
        uTime: { value: 0 },
        uColor1: { value: new THREE.Color(this.scene.colorControls.color1) },
        uColor2: { value: new THREE.Color(this.scene.colorControls.color2) },
        uColor3: { value: new THREE.Color(this.scene.colorControls.color3) },
        uAlpha: { value: 1 },
        uRingPos: { value: new THREE.Vector2(0, 0) },
        uRez: {
          value: new THREE.Vector2(
            this.scene.renderer.domElement.width,
            this.scene.renderer.domElement.height
          ),
        },
        uParticleScale: { value: this.particleScale },
        uPixelRatio: { value: this.scene.pixelRatio },
        uColorScheme: { value: this.colorScheme },
      },
      vertexShader: `
        precision highp float;
        attribute vec4 seeds;

        uniform sampler2D uPosition;
        uniform float uTime;
        uniform float uParticleScale;
        uniform float uPixelRatio;
        uniform int uColorScheme;

        varying vec4 vSeeds;
        varying float vVelocity;
        varying vec2 vLocalPos;
        varying vec2 vScreenPos;
        varying float vScale;

        void main() {

            vec4 pos = texture2D(uPosition, uv);
            vSeeds = seeds;

            vVelocity = pos.w;
            vScale = pos.z;
            vLocalPos = pos.xy;
            vec4 viewSpace  = modelViewMatrix * vec4(vec3(pos.xy, 0.), 1.0);

            gl_Position = projectionMatrix * viewSpace;
            vScreenPos = gl_Position.xy;

            gl_PointSize = ((vScale * 7.) * (uPixelRatio * 0.5) * uParticleScale);

        }
      `,
      fragmentShader: `
        precision highp float;

        varying vec4 vSeeds;
        varying vec2 vScreenPos;
        varying vec2 vLocalPos;
        varying float vScale;
        varying float vVelocity;

        uniform vec3 uColor1;
        uniform vec3 uColor2;
        uniform vec3 uColor3;

        uniform vec2 uRingPos;
        uniform vec2 uRez;

        uniform float uAlpha;
        uniform float uTime;

        uniform int uColorScheme;

        ${NOISE_GLSL}

        #define PI 3.1415926535897932384626433832795

        float sdRoundBox( in vec2 p, in vec2 b, in vec4 r )
        {
            r.xy = (p.x>0.0)?r.xy : r.zw;
            r.x  = (p.y>0.0)?r.x  : r.y;
            vec2 q = abs(p)-b+r.x;
            return min(max(q.x,q.y),0.0) + length(max(q,0.0)) - r.x;
        }

        vec2 rotate(vec2 v, float a) {
            float s = sin(a);
            float c = cos(a);
            mat2 m = mat2(c, s, -s, c);
            return m * v;
        }

        void main() {

            float uBorderSize = 0.2;
            vec2 center = vec2(.48, .4);
            float ratio = uRez.x / uRez.y;

            float noiseAngle = snoise(vec3(vLocalPos * 10. + vec2(18.4924, 72.9744), uTime * .85));
            float noiseColor = snoise(vec3(vLocalPos * 2. + vec2(74.664, 91.556), uTime * .5));
            noiseColor = (noiseColor + 1.) * .5;

            float angle = atan(vLocalPos.y - uRingPos.y, vLocalPos.x - uRingPos.x);

            vec2 uv = gl_PointCoord.xy;
            uv -= vec2(0.5);
            uv.y *= -1.;
            uv = rotate(uv, -angle + (noiseAngle * .5));

            vec2 tuv = vScreenPos;
            tuv = rotate(tuv, uTime * 1.);
            tuv.y *= 1./ratio;
            tuv += .5;

            float h = 0.8;
            float progress = smoothstep(0., .75, pow(noiseColor, 2.));
            vec3 col = mix(mix(uColor1, uColor2, progress/h), mix(uColor2, uColor3, (progress - h)/(1.0 - h)), step(h, progress));
            vec3 color = col;

            float dist = sqrt(dot(uv, uv));

            float dr = .5;
            float t = smoothstep(dr+(uBorderSize + .0001), dr-uBorderSize, dist);
            t = clamp(t, 0., 1.);

            float rounded = sdRoundBox(uv, vec2(0.5, 0.2), vec4(.25));
            rounded = smoothstep(.1, 0., rounded);

            float a = uAlpha * rounded * smoothstep(0.1, 0.2, vScale);

            if(a < 0.01){
                discard;
            }

            color = clamp(color, 0., 1.);
            color = mix(color, color * clamp(vVelocity, 0., 1.), float(uColorScheme));

            gl_FragColor = vec4(color, clamp(a, 0., 1.));

            #ifdef SRGB_TRANSFER
                gl_FragColor = sRGBTransferOETF( gl_FragColor );
            #endif

        }
      `,
      transparent: true,
      depthTest: false,
      depthWrite: false,
    });

    this.mesh = new THREE.Points(geometry, this.renderMaterial);
    this.mesh.position.set(0, 0, 0);
    this.mesh.scale.set(5, 5, 5);
    this.scene.scene.add(this.mesh);
  }

  resize() {
    this.renderMaterial.uniforms.uRez.value = new THREE.Vector2(
      this.scene.renderer.domElement.width,
      this.scene.renderer.domElement.height
    );
    this.renderMaterial.needsUpdate = true;
  }

  update() {
    const e = this.scene.clock.getElapsedTime() - this.lastTime;
    this.lastTime = this.scene.clock.getElapsedTime();

    const t = (this.noise.getVal(this.scene.time * 0.66 + 94.234) - 0.5) * 2;
    const n = (this.noise.getVal(this.scene.time * 0.75 + 21.028) - 0.5) * 2;

    this.cursorPos.set(t * 0.2, n * 0.1);

    if (this.scene.isIntersecting) {
      this.cursorPos.set(
        this.scene.intersectionPoint.x * 0.175 + t * 0.1,
        this.scene.intersectionPoint.y * 0.175 + n * 0.1
      );
      this.ringPos.set(
        this.ringPos.x + (this.cursorPos.x - this.ringPos.x) * 0.02,
        this.ringPos.y + (this.cursorPos.y - this.ringPos.y) * 0.02
      );
    } else {
      this.cursorPos.set(t * 0.2, n * 0.1);
      this.ringPos.set(
        this.ringPos.x + (this.cursorPos.x - this.ringPos.x) * 0.01,
        this.ringPos.y + (this.cursorPos.y - this.ringPos.y) * 0.01
      );
    }

    this.particleScale =
      (this.scene.renderer.domElement.width / this.scene.pixelRatio / 2000) *
      this.scene.particlesScale;

    this.simMaterial.uniforms.uPosition.value = this.everRendered ? this.rt1.texture : this.posTex;
    this.simMaterial.uniforms.uTime.value = this.scene.clock.getElapsedTime();
    this.simMaterial.uniforms.uDeltaTime.value = e;
    this.simMaterial.uniforms.uRingRadius.value =
      0.175 + Math.sin(this.scene.time * 1) * 0.03 + Math.cos(this.scene.time * 3) * 0.02;
    this.simMaterial.uniforms.uRingPos.value = this.ringPos;
    this.simMaterial.uniforms.uRingWidth.value = this.scene.ringWidth;
    this.simMaterial.uniforms.uRingWidth2.value = this.scene.ringWidth2;
    this.simMaterial.uniforms.uRingDisplacement.value = this.scene.ringDisplacement;

    this.renderer.setRenderTarget(this.rt2);
    this.renderer.render(this.simScene, this.simCamera);
    this.renderer.setRenderTarget(null);

    this.renderMaterial.uniforms.uPosition.value = this.everRendered ? this.rt2.texture : this.posTex;
    this.renderMaterial.uniforms.uTime.value = this.scene.clock.getElapsedTime();
    this.renderMaterial.uniforms.uRingPos.value = this.ringPos;
    this.renderMaterial.uniforms.uParticleScale.value = this.particleScale;
  }

  postRender() {
    const e = this.rt1;
    this.rt1 = this.rt2;
    this.rt2 = e;
    this.everRendered = true;
  }

  kill() {
    this.mesh.geometry.dispose();
    this.mesh.material.dispose();
    this.rt1.dispose();
    this.rt2.dispose();
    this.posTex.dispose();
    this.simMaterial.dispose();
    this.renderMaterial.dispose();
  }
}

class MainScene {
  constructor(container, options = {}) {
    this.loaded = false;
    this.theme = options.theme || "dark";
    this.interactive = options.interactive !== false;
    this.pixelRatio = options.pixelRatio || window.devicePixelRatio;
    this.particlesScale = options.particlesScale || 1;
    this.density = options.density || 200;
    this.verbose = options.verbose || false;
    this.container = container;
    this.width = options.width || window.innerWidth;
    this.height = options.height || window.innerHeight;
    this.background = this.theme === "dark" ? new THREE.Color(0) : new THREE.Color(0xffffff);

    this.scene = new THREE.Scene();
    this.scene.background = this.background;

    this.canvas = document.createElement("canvas");
    options.container.appendChild(this.canvas);

    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
      preserveDrawingBuffer: true,
      stencil: false,
      precision: "highp",
    });

    try {
      this.renderer.extensions.get("EXT_color_buffer_float");
    } catch (_e) {}

    this.renderer.setPixelRatio(this.pixelRatio);
    this.renderer.setSize(this.width, this.height, false);

    this.onWindowResize = this.onWindowResize.bind(this);
    this.initCamera();
    this.initScene();
    this.initEvents();

    this.clock = new THREE.Clock();
    this.time = 0;
    this.lastTime = 0;
    this.dt = 0;
    this.skipFrame = false;
    this.isPaused = false;

    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2();
    this.intersectionPoint = new THREE.Vector3();
    this.isIntersecting = false;

    this.raycastPlane = new THREE.Mesh(
      new THREE.PlaneGeometry(12.5, 12.5),
      new THREE.MeshBasicMaterial({
        color: 0xff0000,
        visible: false,
        side: THREE.DoubleSide,
      })
    );
    this.scene.add(this.raycastPlane);
  }

  initEvents() {
    window.addEventListener("resize", this.onWindowResize);
  }

  onWindowResize() {
    const w = this.container.offsetWidth || window.innerWidth;
    const h = this.container.offsetHeight || window.innerHeight;
    this.width = w;
    this.height = h;
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.particles && this.particles.resize();
  }

  initCamera() {
    this.camera = new THREE.PerspectiveCamera(40, this.width / this.height, 0.1, 1000);
    this.camera.position.z = 3.1;
  }

  initScene() {
    this.colorControls = {
      color1: this.theme === "dark" ? "#7189ff" : "#2c64ed",
      color2: this.theme === "dark" ? "#3074f9" : "#f84242",
      color3: this.theme === "dark" ? "#000000" : "#ffcf03",
    };
    this.ringWidth = 0.15;
    this.ringWidth2 = 0.05;
    this.ringDisplacement = 0.15;
    this.initParticles();
    this.onLoaded();
  }

  initParticles() {
    this.particles = new AntigravityParticles(this);
  }

  onLoaded() {
    this.loaded = true;
  }

  stop() {
    this.isPaused = true;
    this.clock.stop();
  }

  resume() {
    this.isPaused = false;
    this.clock.start();
  }

  kill() {
    this.stop();
    window.removeEventListener("resize", this.onWindowResize);
    if (this.raycastPlane) {
      this.scene.remove(this.raycastPlane);
      this.raycastPlane.geometry.dispose();
      this.raycastPlane.material.dispose();
    }
    this.renderer && this.renderer.dispose();
    if (this.canvas && this.canvas.parentElement) {
      this.canvas.parentElement.removeChild(this.canvas);
    }
  }

  preRender() {
    if ((this.dt = this.clock.getElapsedTime() - this.lastTime) > 0.1) {
      this.dt = 0.1;
    }
    this.lastTime = this.clock.getElapsedTime();
    this.time += this.dt;
    this.particles.update();

    if (this.interactive && !this.skipFrame) {
      const e = this.canvas.getBoundingClientRect();
      this.mouse.x = (cursor.x - e.left) * (screen.width / e.width);
      this.mouse.y = (cursor.y - e.top) * (screen.height / e.height);
      this.mouse.x = (this.mouse.x / screen.width) * 2 - 1;
      this.mouse.y = -((this.mouse.y / screen.height) * 2 - 1);
      if (
        this.mouse.x < -1 ||
        this.mouse.x > 1 ||
        this.mouse.y < -1 ||
        this.mouse.y > 1
      ) {
        this.mouseIsOver = false;
      } else {
        this.mouseIsOver = true;
      }
    }

    if ((this.skipFrame = !this.skipFrame)) return;

    this.raycaster.setFromCamera(this.mouse, this.camera);
    const e = this.raycaster.intersectObject(this.raycastPlane);
    if (e.length > 0 && this.mouseIsOver) {
      this.intersectionPoint.copy(e[0].point);
      this.isIntersecting = true;
    } else {
      this.isIntersecting = false;
    }
  }

  render() {
    if (!this.loaded || this.isPaused) return;
    this.preRender();
    this.renderer.setRenderTarget(null);
    this.renderer.autoClear = false;
    this.renderer.clear();
    this.renderer.render(this.scene, this.camera);
    this.postRender();
  }

  postRender() {
    this.particles.postRender();
  }
}

const cursor = { x: 0, y: 0 };
const screen = { width: window.innerWidth, height: window.innerHeight };

window.addEventListener("mousemove", (ev) => {
  cursor.x = ev.clientX;
  cursor.y = ev.clientY;
});
window.addEventListener("resize", () => {
  screen.width = window.innerWidth;
  screen.height = window.innerHeight;
});

export default function AntigravityParticlesBackground({
  theme = "light",
  density = 200,
  particlesScale = 0.75,
  ringWidth = 0.15,
  ringWidth2 = 0.05,
  ringDisplacement = 0.15,
  className = "",
}) {
  const containerRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const options = {
      container,
      theme,
      density,
      particlesScale,
      ringWidth,
      ringWidth2,
      ringDisplacement,
      interactive: true,
      verbose: false,
    };

    const width = container.offsetWidth || window.innerWidth;
    const height = container.offsetHeight || window.innerHeight;

    const main = new MainScene(container, {
      ...options,
      width,
      height,
    });

    let raf = 0;
    let intersecting = false;
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          intersecting = entry.isIntersecting;
          if (entry.isIntersecting) main.resume();
          else main.stop();
        });
      },
      { root: null, rootMargin: "0px", threshold: 0 }
    );
    io.observe(container);

    const loop = () => {
      raf = requestAnimationFrame(loop);
      if (intersecting) main.render();
    };
    loop();

    const cleanup = () => {
      cancelAnimationFrame(raf);
      io.disconnect();
      main.kill();
    };

    return cleanup;
  }, [theme, density, particlesScale, ringWidth, ringWidth2, ringDisplacement]);

  return (
    <div
      ref={containerRef}
      className={`fixed inset-0 z-0 pointer-events-none ${className}`}
      aria-hidden="true"
    />
  );
}
