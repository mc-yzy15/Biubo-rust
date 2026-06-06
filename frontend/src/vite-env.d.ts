/// <reference types="vite/client" />

declare global {
  interface Window {
    rrwebPlayer: new (config: {
      target: HTMLElement;
      props: {
        events: unknown[];
        autoPlay?: boolean;
        width?: number;
        height?: number;
      };
    }) => {
      $destroy?: () => void;
    };
    Globe: any;
  }
}

export {}
