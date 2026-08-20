import type { FaqItem } from '@reactkits.dev/react-engage';

// dropfile-specific help content. This is per-app config (a prop), NOT part of
// the react-engage package — tradingdiary passes its own FAQ, dropfile passes
// this one. Edit freely; no rebuild of react-engage required.
export const DROPFILE_FAQS: FaqItem[] = [
  {
    id: 'df-storage',
    question: 'How long are my files kept?',
    answer:
      'Files automatically expire and are deleted 7 days after upload. Clipboard text is held in memory only and is never written to disk.',
    category: 'General',
  },
  {
    id: 'df-account',
    question: 'Do I need an account?',
    answer:
      'No. dropfile is anonymous — no registration, no login, no tracking. Just drop a file and share the link.',
    category: 'General',
  },
  {
    id: 'df-cli-upload',
    question: 'How do I upload from the terminal?',
    answer: 'Use curl:  curl dropfile.dev -T yourfile.txt',
    category: 'CLI',
  },
  {
    id: 'df-cli-download',
    question: 'How do I download from the terminal?',
    answer: 'Use curl:  curl -O dropfile.dev/ID/yourfile.txt',
    category: 'CLI',
  },
  {
    id: 'df-inbox',
    question: 'What is the Network Inbox?',
    answer:
      'Active files stay discoverable to devices on the same public IP for their 7-day lifetime, so the receiving browser does not need to stay open during upload.',
    category: 'Sharing',
  },
  {
    id: 'df-privacy',
    question: 'Who can see my files?',
    answer:
      'Discovery and real-time sync are localized to your public IP. Anyone with the direct file link can download it until it expires.',
    category: 'Privacy',
  },
];
