import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { TitleBar } from './TitleBar';

export function Layout() {
  return (
    <div className="flex h-screen w-screen overflow-hidden dark">
      <TitleBar />
      <Sidebar />
      <main className="flex-1 overflow-auto bg-surface-950 p-6 pt-12">
        <Outlet />
      </main>
    </div>
  );
}
