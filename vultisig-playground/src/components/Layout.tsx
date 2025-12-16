import { Outlet } from 'react-router-dom'
import ChainMenu from './ChainMenu'

function Layout() {
  return (
    <div className="h-screen bg-gray-50 flex overflow-hidden">
      <aside className="w-64 bg-white border-r border-gray-200 flex-shrink-0 flex flex-col h-full">
        <div className="p-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-3">
            <img 
              src="/logo.svg" 
              alt="Vultisig logo"
              className="w-8 h-8"
            />
            <h1 className="text-xl font-bold text-gray-900">Playground</h1>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto">
          <div className="p-4">
            <ChainMenu />
          </div>
        </nav>
      </aside>

      <main className="flex-1 overflow-y-auto h-full">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

export default Layout

