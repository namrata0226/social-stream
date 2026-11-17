import { Link } from "react-router-dom";
import { Empty } from "../components/ui";
import { MdOutlineSearchOff } from "react-icons/md";

export default function NotFound() {
  return <Empty icon={MdOutlineSearchOff} title="Page not found" text="The page you're looking for doesn't exist or was moved." action={<Link to="/" className="btn-primary">Go home</Link>} />;
}
