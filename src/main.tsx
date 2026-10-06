import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {initializeApiInterceptor} from './apiConfig.ts';
import App from './App.tsx';
import './index.css';

initializeApiInterceptor();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
