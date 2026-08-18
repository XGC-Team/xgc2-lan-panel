import { createRoot } from 'react-dom/client';
import { initializeSkin } from '@xgc2/ui-react';
import '@xgc2/ui-react/styles.css';
import './styles/focus.css';
import './styles/app.css';
import { App } from './App';

initializeSkin({ defaultSkin: 'light' });

createRoot(document.getElementById('root')!).render(<App />);
