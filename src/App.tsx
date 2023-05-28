import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./pages/layout";
import RegisterLogin from "./pages/RegisterLogin";
import './App.css'

function App() {
  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<RegisterLogin />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </>
  )
}

export default App
