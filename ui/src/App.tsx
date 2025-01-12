import { BrowserRouter, Outlet, Route, Routes } from "react-router";
import Dashboard from "./components/Dashboard";
import NavBar from "./components/NavBar";
import { ErrorPage } from "./components/ErrorPage";
import QueryLog from "./components/QueryLog";
import { Hosts } from "./components/Hosts";
import { Denylist } from "./components/Denylist";

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route
                    path="/"
                    element={
                        <div className="flex flex-col sm:flex-row h-screen w-screen min-w-80">
                            <NavBar />
                            <div className="mx-auto w-full h-full p-4 overflow-y-scroll">
                                <Outlet />
                            </div>
                        </div>
                    }>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/log" element={<QueryLog />} />
                    <Route path="/hosts" element={<Hosts />} />
                    <Route path="/denylist" element={<Denylist />} />
                    <Route path="*" element={<ErrorPage />} />
                </Route>
            </Routes>
        </BrowserRouter>
    );
}

export default App;
