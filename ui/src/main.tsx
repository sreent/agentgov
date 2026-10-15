import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { applySavedTheme } from './lib/theme';
import { App } from './shell/App';
import './styles.css';

applySavedTheme();
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
