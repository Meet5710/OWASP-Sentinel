import React from 'react';
import { Sidebar, type ActiveTab, type SidebarProps } from './Sidebar';

export type { ActiveTab, SidebarProps };
export { Sidebar };

// Backward-compatible alias for existing tests and components
export const Navbar: React.FC<SidebarProps> = (props) => {
  return <Sidebar {...props} />;
};

export default Sidebar;
