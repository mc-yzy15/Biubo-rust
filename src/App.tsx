import heroImg from './assets/hero.png'
import './App.css'

function App() {
  return (
    <div className="app">
      <BackgroundGrid />
      <Navigation />
      <HeroSection />
      <FeaturesSection />
      <QuickStartSection />
      <Footer />
    </div>
  )
}

function BackgroundGrid() {
  return (
    <div className="bg-grid">
      <div className="bg-grid-lines"></div>
      <div className="bg-gradient-top"></div>
      <div className="bg-gradient-bottom"></div>
    </div>
  )
}

function Navigation() {
  return (
    <nav className="nav">
      <div className="nav-content">
        <div className="nav-logo">
          <svg className="nav-logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span className="nav-logo-text">BIUBO-RUST</span>
        </div>
        <div className="nav-links">
          <a href="#features" className="nav-link">功能特性</a>
          <a href="#quickstart" className="nav-link">快速开始</a>
          <a href="https://github.com/mc-yzy15/Biubo-rust" target="_blank" rel="noopener noreferrer" className="nav-link nav-github">
            <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            GitHub
          </a>
        </div>
      </div>
    </nav>
  )
}

function HeroSection() {
  return (
    <section className="hero">
      <div className="hero-content">
        <div className="hero-badge animate-in">
          <span className="badge-dot"></span>
          Open Source Release v1.0.0-alpha
        </div>
        
        <h1 className="hero-title animate-in animate-delay-1">
          Empower your security with
          <span className="gradient-text"> AI-driven</span> threat intelligence
        </h1>
        
        <p className="hero-subtitle animate-in animate-delay-2">
          高性能 Rust 语言 Web 应用防火墙，AI 驱动的安全防护与实时威胁检测
        </p>
        
        <div className="hero-command animate-in animate-delay-3">
          <div className="command-label">快速部署</div>
          <div className="command-box">
            <code>$ docker run -d -p 80:80 zplb/biubo:1.1.0</code>
            <button className="command-copy" aria-label="复制命令">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
              </svg>
            </button>
          </div>
        </div>
        
        <p className="hero-tagline animate-in animate-delay-4">
          One command. Zero dependencies. <span className="text-accent">Total protection.</span>
        </p>
      </div>
      
      <div className="hero-visual">
        <div className="hero-glow"></div>
        <img src={heroImg} className="hero-image" alt="Biubo WAF Shield" />
      </div>
      
      <div className="hero-scroll">
        <a href="#features" className="scroll-indicator">
          <span>向下滚动</span>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </a>
      </div>
    </section>
  )
}

function FeaturesSection() {
  return (
    <section id="features" className="features">
      <div className="section-header">
        <h2 className="section-title">
          Beyond Basic <span className="gradient-text">Filtering</span>
        </h2>
        <p className="section-subtitle">
          突破传统 WAF 限制，AI 赋能的下一代安全防护
        </p>
      </div>
      
      <div className="features-grid">
        <FeatureCard
          icon="brain"
          title="Intelligence You Can Trust"
          titleCn="AI 智能检测引擎"
          description="当签名检测失效时，LLM 引擎接管。Biubo 理解复杂载荷的语义意图，检测其他 WAF 遗漏的威胁。"
          features={[
            '多阶段攻击关联分析',
            '混淆技术中和器',
            '语义级 Payload 理解'
          ]}
          gif="assets/GIF_01_AI_DETECTION.gif"
          gifAlt="AI Detection Preview"
          accent="cyan"
        />
        
        <FeatureCard
          icon="replay"
          title="Watch the Hacker's Moves"
          titleCn="会话取证与重放"
          description="告别枯燥的日志分析。像监视攻击者一样回放每个会话，可视化取证证据一键获取。"
          features={[
            '完整 rrweb 录屏集成',
            '精确的鼠标和键盘追踪',
            '可视化会话重放'
          ]}
          gif="assets/GIF_02_RRWEB_REPLAY.gif"
          gifAlt="Visual Replay Preview"
          accent="purple"
        />
        
        <FeatureCard
          icon="globe"
          title="Global Attack Map"
          titleCn="全球攻击态势感知"
          description="可视化战场全局。实时攻击地图提供来自全球威胁的即时态势感知能力。"
          features={[
            '实时 IP 信誉追踪',
            '交互式地理定位仪表板',
            '全球攻击热力图'
          ]}
          gif="assets/GIF_03_ATTACK_MAP.gif"
          gifAlt="Global Map Preview"
          accent="green"
        />
      </div>
    </section>
  )
}

function FeatureCard({ icon, title, titleCn, description, features, gif, gifAlt, accent }: {
  icon: string;
  title: string;
  titleCn: string;
  description: string;
  features: string[];
  gif: string;
  gifAlt: string;
  accent: string;
}) {
  return (
    <div className={`feature-card feature-${accent}`}>
      <div className="feature-header">
        <div className={`feature-icon feature-icon-${accent}`}>
          <FeatureIcon type={icon} />
        </div>
        <div className="feature-titles">
          <h3 className="feature-title">{title}</h3>
          <span className="feature-title-cn">{titleCn}</span>
        </div>
      </div>
      
      <p className="feature-description">{description}</p>
      
      <ul className="feature-list">
        {features.map((feature: string, index: number) => (
          <li key={index} className="feature-list-item">
            <svg className="feature-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            {feature}
          </li>
        ))}
      </ul>
      
      <div className="feature-preview">
        <div className="preview-border"></div>
        <img src={gif} className="preview-image" alt={gifAlt} loading="lazy" />
      </div>
    </div>
  )
}

function FeatureIcon({ type }: { type: string }) {
  switch (type) {
    case 'brain':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M12 2a7 7 0 017 7c0 2.38-1.19 4.47-3 5.74V17a2 2 0 01-2 2h-4a2 2 0 01-2-2v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 017-7z" />
          <path d="M9 21h6M10 17v4M14 17v4" />
        </svg>
      )
    case 'replay':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <polygon points="5 3 19 12 5 21 5 3" />
        </svg>
      )
    case 'globe':
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="12" r="10" />
          <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
        </svg>
      )
    default:
      return null
  }
}

function QuickStartSection() {
  return (
    <section id="quickstart" className="quickstart">
      <div className="section-header">
        <h2 className="section-title">
          Get Started in <span className="gradient-text">Minutes</span>
        </h2>
        <p className="section-subtitle">
          三步部署，即刻防护
        </p>
      </div>
      
      <div className="steps-grid">
        <StepCard
          number="01"
          title="拉取镜像"
          description="一行命令拉取最新 Docker 镜像"
          code="docker pull zplb/biubo:1.1.0"
        />
        <StepCard
          number="02"
          title="运行容器"
          description="映射端口，启动 Biubo WAF"
          code="docker run -d -p 80:80 zplb/biubo:1.1.0"
        />
        <StepCard
          number="03"
          title="开始防护"
          description="访问 localhost 配置规则"
          code="open http://localhost/dashboard"
        />
      </div>
      
      <div className="quickstart-links">
        <a href="https://github.com/mc-yzy15/Biubo-rust" target="_blank" rel="noopener noreferrer" className="quickstart-link">
          <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
          </svg>
          查看源码
        </a>
        <a href="https://github.com/mc-yzy15/Biubo-rust/issues" target="_blank" rel="noopener noreferrer" className="quickstart-link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          报告问题
        </a>
      </div>
    </section>
  )
}

function StepCard({ number, title, description, code }: {
  number: string;
  title: string;
  description: string;
  code: string;
}) {
  return (
    <div className="step-card">
      <div className="step-number">{number}</div>
      <h3 className="step-title">{title}</h3>
      <p className="step-description">{description}</p>
      <div className="step-code">
        <code>{code}</code>
      </div>
    </div>
  )
}

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-brand">
          <svg className="footer-logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span className="footer-brand-text">Biubo-rust</span>
        </div>
        
        <p className="footer-description">
          基于 Rust 构建的高性能 Web 应用防火墙<br />
          Fork自 <a href="https://github.com/BiuboWAF/Biubo" target="_blank" rel="noopener noreferrer" className="footer-link">BiuboWAF/Biubo</a>
        </p>
        
        <div className="footer-links">
          <a href="https://github.com/mc-yzy15/Biubo-rust" target="_blank" rel="noopener noreferrer" className="footer-link-item">
            <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            GitHub
          </a>
        </div>
        
        <div className="footer-bottom">
          <p>MIT Licensed | Built with Rust & ❤️</p>
        </div>
      </div>
    </footer>
  )
}

export default App
