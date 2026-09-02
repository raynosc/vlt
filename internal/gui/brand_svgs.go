package gui

import (
	"fyne.io/fyne/v2"
)

// brandSVGRegistry stores crisp, official vector SVGs for major tech platforms,
// developer tools, and cloud services (Google, Atlassian, AWS, Microsoft, Apple, etc.).
var brandSVGRegistry = map[string]*fyne.StaticResource{
	// ── Financial & Banking (Uruguay & Regional) ──
	"abitab": {
		StaticName: "abitab.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <circle cx="256" cy="256" r="240" fill="#003366"/>
  <circle cx="256" cy="256" r="200" fill="#ffffff"/>
  <circle cx="256" cy="256" r="160" fill="#880033"/>
  <path d="M256 144l96 144h-56l-40-60-40 60h-56z" fill="#ffffff"/>
</svg>`),
	},
	"brou": {
		StaticName: "brou.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#005599"/>
  <path d="M128 320h256v32H128z" fill="#ffcc00"/>
  <path d="M160 272h192v24H160zm32-48h128v24H192zm32-48h64v24h-64zm-48-48h160v24H176z" fill="#ffffff"/>
  <circle cx="256" cy="304" r="16" fill="#005599"/>
</svg>`),
	},
	"itau": {
		StaticName: "itau.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="112" fill="#ec7000"/>
  <circle cx="160" cy="180" r="24" fill="#ffcc00"/>
  <rect x="144" y="224" width="32" height="128" rx="8" fill="#ffffff"/>
  <path d="M216 192v32h-24v24h24v72c0 24 12 36 36 36h20v-24h-16c-8 0-12-4-12-12v-72h32v-24h-32v-32h-28z" fill="#ffffff"/>
  <path d="M336 220c-36 0-56 24-56 56s20 56 56 56c16 0 28-6 36-16v16h28V224h-28v14c-8-11-20-18-36-18zm8 88c-20 0-32-14-32-32s12-32 32-32 32 14 32 32-12 32-32 32z" fill="#ffffff"/>
</svg>`),
	},
	"santander": {
		StaticName: "santander.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#ec0000"/>
  <path d="M256 112c-48 48-80 96-80 144 0 44 36 80 80 80s80-36 80-80c0-48-32-96-80-144zm0 256c-62 0-112-50-112-112 0-48 32-104 64-144-16 32-32 80-32 112 0 44 36 80 80 80 24 0 46-11 60-28-12 30-34 52-60 52zm0-48c-35 0-64-29-64-64 0-32 24-72 64-112 40 40 64 80 64 112 0 35-29 64-64 64z" fill="#ffffff"/>
</svg>`),
	},
	"scotiabank": {
		StaticName: "scotiabank.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#ec111a"/>
  <path d="M352 144c-32-16-72-16-104 0l-80 48c-32 19-48 54-40 91 8 37 38 65 76 70l64 9c24 3 40 18 36 38-4 20-24 32-48 29-28-4-52-19-68-43l-36 24c24 36 60 59 104 64 48 6 92-18 100-66 8-48-24-88-72-95l-64-9c-20-3-32-15-28-29 4-15 20-25 36-23 24 3 44 15 56 35l36-24c-18-30-48-48-84-53v-6z" fill="#ffffff"/>
</svg>`),
	},
	"midinero": {
		StaticName: "midinero.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#00b074"/>
  <circle cx="256" cy="256" r="144" fill="none" stroke="#ffffff" stroke-width="36"/>
  <circle cx="256" cy="256" r="64" fill="#ffffff"/>
</svg>`),
	},
	"bna": {
		StaticName: "bna.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#1c6e8c"/>
  <path d="M256 112L112 192h288L256 112zm-128 96h32v128h-32V208zm64 0h32v128h-32V208zm64 0h32v128h-32V208zm64 0h32v128h-32V208zm64 0h32v128h-32V208zm-272 144h320v32H112v-32z" fill="#ffffff"/>
</svg>`),
	},
	"btgpactual": {
		StaticName: "btgpactual.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0a2240"/>
  <circle cx="208" cy="256" r="96" fill="none" stroke="#ffffff" stroke-width="24"/>
  <path d="M176 208h48c18 0 32 10 32 24s-14 24-32 24h-48v-48zm0 48h52c18 0 32 10 32 24s-14 24-32 24h-52v-48z" fill="#ffffff"/>
</svg>`),
	},
	"bandes": {
		StaticName: "bandes.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <circle cx="256" cy="256" r="224" fill="#d4141e"/>
  <circle cx="256" cy="256" r="176" fill="#ffffff"/>
  <path d="M192 160h64c24 0 40 16 40 36 0 16-10 28-24 32 20 4 32 20 32 40 0 24-20 44-48 44h-64V160zm40 64h24c8 0 16-6 16-14s-8-14-16-14h-24v28zm0 56h28c10 0 18-6 18-16s-8-16-18-16h-28v32z" fill="#d4141e"/>
</svg>`),
	},
	"heritage": {
		StaticName: "heritage.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#222222"/>
  <path d="M192 128h32v256h-32zm96 0h32v256h-32zm-160 96h256v32H128zm0 96h256v32H128z" fill="#ffffff"/>
</svg>`),
	},

	// ── Microsoft & Cloud ──
	"azure": {
		StaticName: "azure.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M125.7 427.6h126.9L391.8 84.4H240.2L125.7 427.6z" fill="#0078d4"/>
  <path d="M125.7 427.6L272.9 295l-71.1-137.9L73 427.6h52.7z" fill="#50e6ff"/>
  <path d="M386.3 84.4H240.2l-38.4 114.7 71.1 137.9L439 427.6h-52.7L252.6 150.3l133.7-65.9z" fill="#0078d4" opacity="0.9"/>
</svg>`),
	},
	"microsoft": {
		StaticName: "microsoft.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect x="48" y="48" width="192" height="192" fill="#f25022"/>
  <rect x="272" y="48" width="192" height="192" fill="#7fba00"/>
  <rect x="48" y="272" width="192" height="192" fill="#00a4ef"/>
  <rect x="272" y="272" width="192" height="192" fill="#ffb900"/>
</svg>`),
	},
	"outlook": {
		StaticName: "outlook.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M288 96h144c17.7 0 32 14.3 32 32v256c0 17.7-14.3 32-32 32H288V96z" fill="#0072c6"/>
  <path d="M464 128l-176 128-176-128h352z" fill="#50e6ff" opacity="0.85"/>
  <rect x="48" y="144" width="224" height="224" rx="40" fill="#0072c6"/>
  <circle cx="160" cy="256" r="64" fill="none" stroke="#ffffff" stroke-width="28"/>
</svg>`),
	},

	// ── Google Suite ──
	"google": {
		StaticName: "google.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#ffffff"/>
  <path d="M432.2 259.9c0-14.1-1.5-28.5-4.4-42.4H256v81.5h99.1c-4.1 23.7-17.8 44.2-37.3 57.9v48.6h60.8c35.6-33.7 54.6-83.7 54.6-145.6z" fill="#4285f4"/>
  <path d="M256 444c50.4 0 93.3-16.7 124.7-45.3l-60.8-48.6c-16.7 11.2-38 18-63.9 18-48.8 0-90.9-33.4-105.1-78.1H86.4v50.4C117.5 401 180.3 444 256 444z" fill="#34a853"/>
  <path d="M150.9 288c-3.4-10.2-5.9-22.3-5.9-32s2.5-21.8 5.9-32v-50.4H86.4C72.7 200.9 64 227.9 64 256s8.7 55.1 22.4 82.4l64.5-50.4z" fill="#fbbc05"/>
  <path d="M256 139.9c27.3 0 52.3 9.1 71.1 27l53.1-53.1C348.1 82.5 306.2 68 256 68c-75.7 0-138.5 43-169.6 105.6l64.5 50.4c14.2-44.7 56.3-84.1 105.1-84.1z" fill="#ea4335"/>
</svg>`),
	},
	"gmail": {
		StaticName: "gmail.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M72 136v240c0 22.1 17.9 40 40 40h48V256L72 196v-60z" fill="#4285f4"/>
  <path d="M352 416h48c22.1 0 40-17.9 40-40V136l-88 60v220z" fill="#34a853"/>
  <path d="M352 196l88-60-24-18c-17.4-13-41.6-10.4-55.8 5.8L256 216 151.8 123.8c-14.2-16.2-38.4-18.8-55.8-5.8L72 136l88 60 96 74 96-74z" fill="#ea4335"/>
  <path d="M160 256v160h192V256l-96 74-96-74z" fill="#fbbc05"/>
</svg>`),
	},
	"drive": {
		StaticName: "drive.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M182 64h148l146 256H328L182 64z" fill="#ffba00"/>
  <path d="M36 320l74-128 146 256H110L36 320z" fill="#00ac47"/>
  <path d="M182 64l74 128-74 128H36L110 64h72z" fill="#0066da"/>
</svg>`),
	},
	"youtube": {
		StaticName: "youtube.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M490.2 140.4c-5.8-21.7-22.8-38.8-44.5-44.6C406.4 84.4 256 84.4 256 84.4s-150.4 0-189.7 11.4c-21.7 5.8-38.8 22.8-44.5 44.6C10.4 179.7 10.4 256 10.4 256s0 76.3 11.4 115.6c5.8 21.7 22.8 38.8 44.5 44.6 39.3 11.4 189.7 11.4 189.7 11.4s150.4 0 189.7-11.4c21.7-5.8 38.8-22.8 44.5-44.6 11.4-39.3 11.4-115.6 11.4-115.6s0-76.3-11.4-115.6z" fill="#ff0000"/>
  <path d="M206.8 335.6l128-79.6-128-79.6v159.2z" fill="#ffffff"/>
</svg>`),
	},

	// ── Browser & Arc ──
	"arc": {
		StaticName: "arc.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#18181b"/>
  <path d="M120 320c40-100 120-140 180-80 40-40 80-40 100-20-30 40-70 60-120 20-40-30-90-10-120 60l-40 20z" fill="#ffffff"/>
</svg>`),
	},

	// ── Amazon & AWS ──
	"amazon": {
		StaticName: "amazon.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#131921"/>
  <path d="M318.4 233.2c-2.8-21.7-18.4-32.9-46.8-32.9-32.2 0-51.8 14-53.2 38.5 0 21.7 14.7 32.2 41.3 32.2 34.3 0 55.9-15.4 58.7-37.8zm49 84.7h-44.8v-17.5c-15.4 14.7-37.1 21.7-65.1 21.7-47.6 0-82.6-26.6-82.6-67.9 0-46.2 37.8-66.5 89.6-66.5 20.3 0 38.5 3.5 53.9 9.8v-12.6c0-26.6-18.2-40.6-50.4-40.6-25.2 0-48.3 8.4-66.5 21.7l-21-34.3c24.5-18.2 59.5-28.7 94.5-28.7 65.1 0 88.2 32.2 88.2 86.8v128h-4.8v0.8z" fill="#ffffff"/>
  <path d="M102 370c112 56 224 56 308 0-21 21-49 35-83 39-69 9-153-11-225-39z" fill="#ff9900"/>
  <path d="M396 350c6 4 14 3 20-3 2-2 11-13 14-17-4 2-15 5-21 6-7 1-13-1-13-1l-0 15z" fill="#ff9900"/>
</svg>`),
	},
	"aws": {
		StaticName: "aws.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#232f3e"/>
  <!-- a -->
  <path d="M168 252c-2-18-16-28-38-28-24 0-38 12-40 30h24c2-8 8-12 16-12 10 0 16 5 16 14v5c-8-4-18-6-28-6-30 0-46 15-46 37 0 21 16 36 40 36 16 0 28-8 34-19v17h22V252zm-22 36c0 14-10 22-24 22-11 0-18-7-18-17 0-11 8-18 22-18 8 0 14 2 20 5v8z" fill="#ffffff"/>
  <!-- w -->
  <path d="M280 226l-22 88h-24l-18-62-18 62h-24l-22-88h26l12 56 16-56h20l16 56 12-56h26z" fill="#ffffff"/>
  <!-- s -->
  <path d="M374 250c0-16-14-26-36-26-24 0-38 12-40 28h24c2-6 8-10 16-10 8 0 12 3 12 8 0 4-4 7-14 9l-14 4c-20 5-30 15-30 29 0 18 16 28 38 28 24 0 40-12 42-28h-24c-2 6-8 10-18 10-8 0-14-4-14-9 0-5 4-8 14-10l14-4c22-5 32-13 32-29z" fill="#ffffff"/>
  <!-- smile arrow -->
  <path d="M96 358c96 52 216 52 300 0-20 20-48 34-82 38-68 8-148-10-218-38z" fill="#ff9900"/>
  <path d="M386 342c6 4 14 3 19-3 3-2 11-13 14-17-4 2-15 5-21 6-7 1-12-1-12-1v15z" fill="#ff9900"/>
</svg>`),
	},

	// ── Atlassian Suite ──
	"atlassian": {
		StaticName: "atlassian.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0052cc"/>
  <path d="M246.4 216c-4.8-6.4-12.8-9.6-20.8-9.6s-17.6 4.8-22.4 12.8L67.2 425.6c-4.8 8-4.8 17.6 0 25.6 4.8 8 12.8 12.8 22.4 12.8h140.8c12.8 0 24-9.6 25.6-22.4l20.8-203.2c0-8-4.8-16-14.4-22.4z" fill="#ffffff" opacity="0.8"/>
  <path d="M265.6 88l-20.8 203.2c0 8 4.8 16 14.4 22.4 4.8 6.4 12.8 9.6 20.8 9.6s17.6-4.8 22.4-12.8l136-206.4c4.8-8 4.8-17.6 0-25.6-4.8-8-12.8-12.8-22.4-12.8H275.2c-12.8 0-24 9.6-25.6 22.4z" fill="#ffffff"/>
</svg>`),
	},
	"jira": {
		StaticName: "jira.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0052cc"/>
  <path d="M416 240L272 96l-40 40 104 104-104 104 40 40 144-144z" fill="#ffffff"/>
  <path d="M280 240L176 136l-40 40 64 64-64 64 40 40 104-104z" fill="#ffffff" opacity="0.8"/>
</svg>`),
	},
	"confluence": {
		StaticName: "confluence.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0052cc"/>
  <path d="M128 192c32-64 96-96 160-64l64 32c32 16 48 48 32 80l-48 96c-32 64-96 96-160 64l-64-32c-32-16-48-48-32-80l48-96z" fill="#ffffff" opacity="0.8"/>
  <path d="M224 224c16-32 48-48 80-32l48 24c16 8 24 24 16 40l-32 64c-16 32-48 48-80 32l-48-24c-16-8-24-24-16-40l32-64z" fill="#ffffff"/>
</svg>`),
	},
	"bitbucket": {
		StaticName: "bitbucket.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0052cc"/>
  <path d="M439.4 100.8c-4.2-6.5-11.4-10.4-19.1-10.4H91.7c-7.7 0-14.9 3.9-19.1 10.4-4.2 6.5-4.8 14.7-1.6 21.7l64.1 278.6c4.6 20 22.4 34.1 43 34.1h155.8c20.6 0 38.4-14.1 43-34.1l64.1-278.6c3.2-7 2.6-15.2-1.6-21.7zM293.4 298.7h-74.8l-18.7-106.7h112.2l-18.7 106.7z" fill="#ffffff"/>
  <path d="M293.4 298.7l-18.7 106.7h-37.4l-18.7-106.7h74.8z" fill="#2684ff"/>
</svg>`),
	},
	"trello": {
		StaticName: "trello.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0079bf"/>
  <rect x="96" y="96" width="128" height="288" rx="24" fill="#ffffff"/>
  <rect x="288" y="96" width="128" height="176" rx="24" fill="#ffffff"/>
</svg>`),
	},

	// ── Git & Development ──
	"github": {
		StaticName: "github.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#181717"/>
  <path fill-rule="evenodd" clip-rule="evenodd" d="M256 64C150.3 64 64 150.8 64 257.4c0 85.3 54.2 158.1 129.2 183.3 9.2 1.8 13.3-4.1 13.3-9.1v-32.6c-52.3 11.8-63.5-26.8-63.5-26.8-8.2-22.5-20.9-28.6-20.9-28.6-17.3-12.2 1.5-11.9 1.5-11.9 19.5 1.4 29.3 20.7 29.3 20.7 17 29.1 44.4 21 55.2 16.1 1.7-12.8 6.8-21 12.2-25.7-41.7-4.8-86-21.5-86-96.5 0-21.1 7.7-38.6 19-51.6-1.9-4.8-8-24.2 1.9-50.8 0 0 15.8-5.2 52.6 19.5 15.1-4.2 31.3-6.4 47.2-6.5 16.1.1 32.3 2.3 47.2 6.5 36.8-24.7 52.5-19.5 52.5-19.5 10.3 26.6 4.2 46 2.3 50.8 12.4 13 19 30.5 19 51.6 0 75.2-44.4 91.6-86.3 96.3 7 6.1 13.2 17.5 13.2 35.3v53.7c0 5.1 3.5 11.1 13.4 9.1C393.9 415.4 448 342.6 448 257.4 448 150.8 361.7 64 256 64z" fill="#ffffff"/>
</svg>`),
	},
	"gitlab": {
		StaticName: "gitlab.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#18181b"/>
  <path d="M468.1 160.6L437.1 65.7c-5.4-16.7-28.9-16.7-34.4 0l-30.4 94.9H139.7L109.3 65.7c-5.4-16.7-28.9-16.7-34.4 0L43.9 160.6c-5.4 16.7 0.5 35.1 14.7 45.4L256 376.7l197.4-170.7c14.2-10.3 20.1-28.7 14.7-45.4z" fill="#e24329"/>
  <path d="M256 376.7L139.7 160.6h232.6L256 376.7z" fill="#e24329"/>
  <path d="M256 376.7L372.3 160.6h95.8L256 376.7z" fill="#fc6d26"/>
  <path d="M468.1 160.6l-31-94.9c-5.4-16.7-28.9-16.7-34.4 0l-30.4 94.9h95.8z" fill="#fca326"/>
  <path d="M256 376.7L139.7 160.6H43.9L256 376.7z" fill="#fc6d26"/>
  <path d="M43.9 160.6L74.9 65.7c5.4-16.7 28.9-16.7 34.4 0l30.4 94.9H43.9z" fill="#fca326"/>
</svg>`),
	},
	"docker": {
		StaticName: "docker.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#0db7ed"/>
  <path d="M440 240c-8-6.4-24-8-35.2-3.2-4.8-9.6-11.2-19.2-20.8-25.6-3.2 0-6.4-1.6-9.6-1.6-1.6-12.8-8-24-19.2-33.6l-12.8 9.6c8 8 11.2 16 11.2 27.2 0 3.2 0 6.4-1.6 9.6-17.6-4.8-40 1.6-51.2 14.4H64c-9.6 0-16 6.4-16 16 0 72 48 144 144 144 104 0 176-64 208-136 12.8 1.6 27.2-1.6 36.8-11.2 14.4-14.4 19.2-27.2 51.2-12.8v-6.4z" fill="#ffffff"/>
  <rect x="136" y="192" width="40" height="36" rx="6" fill="#ffffff"/>
  <rect x="192" y="192" width="40" height="36" rx="6" fill="#ffffff"/>
  <rect x="248" y="192" width="40" height="36" rx="6" fill="#ffffff"/>
  <rect x="192" y="144" width="40" height="36" rx="6" fill="#ffffff"/>
  <rect x="248" y="144" width="40" height="36" rx="6" fill="#ffffff"/>
</svg>`),
	},
	"kubernetes": {
		StaticName: "kubernetes.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#326ce5"/>
  <circle cx="256" cy="256" r="64" fill="#ffffff"/>
  <path d="M256 128v64m0 128v64m-110.8-192l55.4 32m110.8 64l55.4 32m-221.6 0l55.4-32m110.8-64l55.4-32" stroke="#ffffff" stroke-width="24" stroke-linecap="round"/>
</svg>`),
	},
	"npm": {
		StaticName: "npm.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="64" fill="#cb3837"/>
  <path d="M96 160h320v192H256v-64h-64v64H96V160zm64 64v64h32v-64h-32zm128 0v64h32v-64h-32z" fill="#ffffff"/>
</svg>`),
	},

	// ── Productivity & Communication ──
	"slack": {
		StaticName: "slack.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M112 280a40 40 0 01-40-40 40 40 0 0140-40h40v80h-40zm56 0a40 40 0 0140-40 40 40 0 0140 40v96a40 40 0 01-40 40 40 40 0 01-40-40v-96z" fill="#36c5f0"/>
  <path d="M232 112a40 40 0 0140-40 40 40 0 0140 40v40h-80v-40zm0 56a40 40 0 0140-40 40 40 0 0140 40h96a40 40 0 0140 40 40 40 0 01-40 40h-96z" fill="#2eb67d"/>
  <path d="M400 232a40 40 0 0140 40 40 40 0 01-40 40h-40v-80h40zm-56 0a40 40 0 01-40 40 40 40 0 01-40-40v-96a40 40 0 0140-40 40 40 0 0140 40v96z" fill="#ecb22e"/>
  <path d="M280 400a40 40 0 01-40 40 40 40 0 01-40-40v-40h80v40zm0-56a40 40 0 01-40 40 40 40 0 01-40-40h-96a40 40 0 01-40-40 40 40 0 0140-40h96z" fill="#e01e5a"/>
</svg>`),
	},
	"discord": {
		StaticName: "discord.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <path d="M416 104s-40-28.8-84.8-36.8c-4.8 11.2-11.2 25.6-16 35.2-46.4-6.4-92.8-6.4-139.2 0-4.8-9.6-11.2-24-16-35.2C115.2 75.2 75.2 104 75.2 104 17.6 192 1.6 278.4 9.6 363.2c49.6 36.8 97.6 59.2 144 60.8 11.2-16 22.4-32 30.4-49.6-17.6-6.4-33.6-16-48-27.2 4.8-3.2 8-6.4 12.8-9.6 92.8 43.2 193.6 43.2 284.8 0 4.8 3.2 8 6.4 12.8 9.6-14.4 11.2-30.4 20.8-48 27.2 8 17.6 19.2 33.6 30.4 49.6 46.4-1.6 94.4-24 144-60.8 9.6-99.2-14.4-185.6-76.8-259.2zM176 304c-27.2 0-48-24-48-54.4s20.8-54.4 48-54.4 48 24 48 54.4-20.8 54.4-48 54.4zm160 0c-27.2 0-48-24-48-54.4s20.8-54.4 48-54.4 48 24 48 54.4-20.8 54.4-48 54.4z" fill="#5865f2"/>
</svg>`),
	},
	"1password": {
		StaticName: "1password.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <circle cx="256" cy="256" r="224" fill="#0a85ea"/>
  <circle cx="256" cy="256" r="160" fill="#ffffff"/>
  <circle cx="256" cy="256" r="112" fill="#0a85ea"/>
  <rect x="232" y="176" width="48" height="160" rx="24" fill="#ffffff"/>
</svg>`),
	},
	"firefox": {
		StaticName: "firefox.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <circle cx="256" cy="256" r="224" fill="#ff7139"/>
  <circle cx="256" cy="256" r="160" fill="#0060df"/>
  <path d="M256 64C150 64 64 150 64 256c0 106 86 192 192 192 88 0 162-59.2 184-140.8-6.4 3.2-12.8 4.8-19.2 4.8-35.2 0-64-28.8-64-64 0-19.2 8-35.2 22.4-46.4-12.8-6.4-27.2-9.6-43.2-9.6-52.8 0-96 43.2-96 96 0 9.6 1.6 19.2 4.8 27.2C196.8 296 160 240 160 176c0-36.8 12.8-70.4 33.6-97.6 17.6 25.6 46.4 41.6 78.4 41.6 52.8 0 96-43.2 96-96 0-9.6-1.6-19.2-4.8-27.2-34.4 20-72 31.2-107.2 31.2z" fill="#ffe900"/>
</svg>`),
	},
	"apple": {
		StaticName: "apple.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#18181b"/>
  <path d="M360 268.8c0-56 44.8-83.2 46.4-84.8-25.6-38.4-65.6-43.2-80-43.2-33.6-3.2-65.6 19.2-83.2 19.2s-43.2-19.2-72-19.2c-36.8 0-70.4 20.8-89.6 54.4-38.4 65.6-9.6 163.2 27.2 216 17.6 25.6 40 54.4 67.2 52.8 27.2-1.6 36.8-17.6 68.8-17.6s41.6 17.6 68.8 16c28.8 0 48-25.6 65.6-51.2 20.8-30.4 28.8-59.2 28.8-60.8-1.6-1.6-48-19.2-48-81.6zM300.8 104c14.4-19.2 25.6-44.8 22.4-72-22.4 1.6-49.6 14.4-64 33.6-12.8 16-24 41.6-20.8 67.2 25.6 1.6 48-11.2 62.4-28.8z" fill="#ffffff"/>
</svg>`),
	},
	"cloudflare": {
		StaticName: "cloudflare.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#18181b"/>
  <path d="M396.8 220.8c-9.6-60.8-60.8-108.8-124.8-108.8-52.8 0-99.2 32-116.8 80-44.8 4.8-80 43.2-80 89.6 0 49.6 40 89.6 89.6 89.6h232c46.4 0 83.2-36.8 83.2-83.2 0-38.4-25.6-72-62.4-81.6-6.4-4.8-12.8-11.2-20.8-14.4v-1.2z" fill="#f38020"/>
  <path d="M372.8 264h-24c-3.2-11.2-9.6-20.8-19.2-27.2-9.6-6.4-20.8-9.6-32-9.6-22.4 0-41.6 14.4-48 36.8h-19.2c-4.8 0-9.6 3.2-9.6 8s4.8 8 9.6 8h142.4c4.8 0 9.6-3.2 9.6-8s-4.8-8-9.6-8z" fill="#faad3f"/>
</svg>`),
	},
	"notion": {
		StaticName: "notion.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#000000"/>
  <path d="M112 96l216 24c16 1.6 24 12.8 24 27.2v232c0 16-12.8 28.8-28.8 28.8L104 384c-16 0-24-12.8-24-27.2V124.8c0-16 12.8-28.8 32-28.8zm48 72v160l56-8V160l-56 8zm88-8v160l80-8V152l-80 8z" fill="#ffffff"/>
</svg>`),
	},
	"server": {
		StaticName: "server.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect x="48" y="64" width="416" height="104" rx="20" fill="#1e293b"/>
  <rect x="48" y="64" width="416" height="104" rx="20" fill="none" stroke="#3b82f6" stroke-width="8"/>
  <circle cx="104" cy="116" r="16" fill="#10b981"/>
  <circle cx="148" cy="116" r="16" fill="#3b82f6"/>
  <rect x="220" y="108" width="192" height="16" rx="8" fill="#64748b"/>
  <rect x="48" y="204" width="416" height="104" rx="20" fill="#1e293b"/>
  <rect x="48" y="204" width="416" height="104" rx="20" fill="none" stroke="#3b82f6" stroke-width="8"/>
  <circle cx="104" cy="256" r="16" fill="#10b981"/>
  <circle cx="148" cy="256" r="16" fill="#3b82f6"/>
  <rect x="220" y="248" width="192" height="16" rx="8" fill="#64748b"/>
  <rect x="48" y="344" width="416" height="104" rx="20" fill="#1e293b"/>
  <rect x="48" y="344" width="416" height="104" rx="20" fill="none" stroke="#3b82f6" stroke-width="8"/>
  <circle cx="104" cy="396" r="16" fill="#10b981"/>
  <circle cx="148" cy="396" r="16" fill="#3b82f6"/>
  <rect x="220" y="388" width="192" height="16" rx="8" fill="#64748b"/>
</svg>`),
	},
	"terminal": {
		StaticName: "terminal.svg",
		StaticContent: []byte(`<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="96" fill="#090d16"/>
  <rect x="16" y="16" width="480" height="480" rx="80" fill="#1e293b"/>
  <circle cx="72" cy="72" r="14" fill="#ef4444"/>
  <circle cx="112" cy="72" r="14" fill="#f59e0b"/>
  <circle cx="152" cy="72" r="14" fill="#10b981"/>
  <path d="M120 180l88 76-88 76" fill="none" stroke="#10b981" stroke-width="28" stroke-linecap="round" stroke-linejoin="round"/>
  <rect x="240" y="316" width="144" height="20" rx="6" fill="#f8fafc"/>
</svg>`),
	},
}
