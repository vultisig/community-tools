import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Home from './pages/Home'
import ProviderPlayground from './pages/ProviderPlayground'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Home />} />
        <Route path=":chain/:provider" element={<ProviderPlayground />} />
      </Route>
    </Routes>
  )
}

export default App

