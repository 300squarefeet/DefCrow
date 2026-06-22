export default function CrowLogo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-label="DefCrow logo">
      <defs>
        <linearGradient id="crowFeather" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--logo-a, #0e1a36)"/>
          <stop offset="1" stopColor="var(--logo-b, #1f56e0)"/>
        </linearGradient>
      </defs>
      <path d="M9 35c0-12 11-22 23-22 7 0 13 3 17 8l9-2-5 7c2 4 2 9 0 13-3 9-12 14-21 14-11 0-23-7-23-18z" fill="url(#crowFeather)"/>
      <path d="M14 35c4 2 9 3 14 3 6 0 12-1 17-4-3 9-11 14-19 14-5 0-10-2-13-6" fill="var(--logo-c, #06112a)" opacity="0.55"/>
      <path d="M52 21l11 1-9 5z" fill="var(--logo-beak, #f5b400)"/>
      <path d="M52 21l11 1-9 5z" fill="none" stroke="var(--logo-beak-dark, #c98a00)" strokeWidth="0.7"/>
      <circle cx="46" cy="23" r="2.4" fill="#f8fafc"/>
      <circle cx="46.6" cy="23" r="1.2" fill="#06112a"/>
      <path d="M28 18c2-3 6-4 9-3M22 22c2-2 5-3 8-2" stroke="var(--logo-c, #06112a)" strokeWidth="0.9" fill="none" opacity="0.55"/>
    </svg>
  )
}
